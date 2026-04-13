# PQC Multisig V3.1: Analysis Companion

> **Status:** DRAFT v1.1 — companion to `PQC_MULTISIG.md` v1.1
> **Purpose:** Size analysis, attack catalog, cryptographer review targets, wargame history, and design rationale documented in detail so the spec itself stays prescriptive and tight.

---

## Table of Contents

1. [Design History](#1-design-history)
2. [Receiving Model Tradeoff Analysis](#2-receiving-model-tradeoff-analysis)
3. [Sizing and Chain Impact](#3-sizing-and-chain-impact)
4. [Attack Catalog](#4-attack-catalog)
5. [Wargame Round Summaries](#5-wargame-round-summaries)
6. [Rationale for Deferring Full Rotation to V3.2](#6-rationale-for-deferring-full-rotation-to-v32)
7. [Cryptographer Review Targets](#7-cryptographer-review-targets)
8. [Open Questions and Future Work](#8-open-questions-and-future-work)

---

## 1. Design History

V3.1 multisig emerged from the recognition that the original
`PQC_MULTISIG.md` coordinator design encoded a power asymmetry that
multisig users typically do not want. A coordinator role concentrated
proposal, construction, signing-assembly, and broadcast under one
participant, and the non-interactive `scheme_id=2` scheme already in
consensus did not actually require such a role.

The design evolved through three distinct phases:

**Phase 1 — Split drafts.** Governance and receiving were specified in
separate documents to let the receiving model (Option C per-output
forward privacy via N-fold KEM fan-out) be evaluated independently of
the governance model (equal participants with rotating prover).

**Phase 2 — Consolidation into v1.0.** After Round 1 and Round 2 of
adversarial wargaming, the two drafts were merged into a single
consolidated spec (v1.0). This fixed several issues raised by both
reviewers (address-file substitution, rate limit bypass, relay
centralization, tiebreaker grindability).

**Phase 3 — Round 3 wargame and verification gap resolution → v1.1.**
A third round of review identified a fatal flaw in v1.0: the
prover-assignment verification in §11.3 referenced
`group.kem_shared_secrets` as if each participant could access all N
shared secrets, which is cryptographically impossible. Each participant
can decap only their own KEM ciphertext. The verification mechanism as
specified was non-implementable, which meant the rotating-prover
security claim was false.

Two independent analyses converged on **Solution C**: independent
per-participant classical spend-auth secrets derived via domain-separated
KDF, with all N classical spend-auth public keys published in `tx_extra`.
This made verification use only publicly-verifiable data and resolved
the verification gap.

The second analysis additionally proposed a versioned
`SpendAuthPubkey` abstraction that would enable future PQC prover
backends (e.g., ML-DSA-65 per-output, or FROST-threshold SAL) to slot
in without protocol rewrite. This was adopted via the `spend_auth_version`
byte in both address format and `tx_extra` tag 0x0A.

v1.1 also incorporated four additional Round 3 findings:

- `kem_shared_secrets` reference in v1.0 §11.3 replaced with persisted
  `spend_auth_pubkeys` list
- Full receive-time validation (§8.3) added to catch time-bomb outputs
  before they enter balance
- ProverReceipt mechanism strengthened with monotonic local_counter to
  detect prover equivocation
- CounterProof advancement lineage formalized with exact-match rules
  on consumed inputs

---

## 2. Receiving Model Tradeoff Analysis

### 2.1 Options considered

The receiving side was evaluated across four options:

| Option | Description | Per-output size | Forward privacy |
|---|---|---|---|
| A | Single KEM encap to group-aggregate pubkey | ~1.2 KB | None; group key compromise → all outputs exposed |
| B | Single KEM encap; shared secret split via OPRF | ~1.3 KB | Partial; requires per-spend OPRF ceremony |
| C | N parallel KEM encaps; per-participant ephemeral key derivation | ~N × 1.2 KB | Full per-output forward privacy |
| D | N parallel KEM encaps + N classical spend-auth pubkeys in tx_extra | ~N × 1.25 KB | Full per-output forward privacy + public prover verification |

**Option D** (the Solution C refinement of Option C) was selected. The
marginal size cost over Option C is ~32 bytes per participant for the
published classical spend-auth pubkey — approximately 2.5% overhead —
in exchange for making prover-assignment verification use purely public
data.

### 2.2 Why not Option A

Option A concentrates forward-privacy risk: a single compromise of the
group's aggregate KEM key exposes all past outputs scannable. Worse, the
aggregate key is a committee secret that must be rotated through some
threshold ceremony, pushing complexity into the governance layer. Option
A's size advantage (~1.2 KB per output regardless of N) is real but the
security tradeoff is unfavorable for a long-lived group.

### 2.3 Why not Option B

OPRF-based models require per-spend online ceremonies between the spender
and the group, which breaks the deterministic-construction property that
V3.1 depends on for symmetric authority. A participant producing a
spend cannot complete the construction alone; this re-introduces
centralization pressure (one participant acts as the OPRF server).

### 2.4 Why Option C/D

The marginal cost per output is `N × (KEM ciphertext + ephemeral pubkey
+ spend-auth pubkey + view tag hint) ≈ N × 1.25 KB`. For N=5 this is
~6 KB per multisig-recipient output. Large, but:

- Paid once per output, not per spend
- Only for multisig-recipient outputs (not all outputs)
- Permits full per-output forward privacy
- Permits deterministic construction
- Permits purely public prover-assignment verification (Solution C
  refinement)

The forward-privacy property is the primary acceptance criterion. V3.1
accepts the size cost explicitly.

---

## 3. Sizing and Chain Impact

### 3.1 Per-output size (multisig-recipient)

| Component | Size |
|---|---|
| Output public key O | 32 B |
| Amount commitment | 32 B |
| ECDH info (standard) | 32 B |
| **Multisig-specific tx_extra:** | |
| Tag 0x06 KEM ciphertexts (N × 1120 B) | 1120 × N B |
| Tag 0x07 leaf hash (32 B) | 32 B |
| Tag 0x09 view tag hints (N × 1 B) | N B |
| Tag 0x0A spend-auth pubkeys (1 + N × 32 B) | 1 + 32 × N B |
| **Total multisig-specific overhead** | **33 + 1153 × N B** |

Per output totals:

| N | Multisig-specific | Total output bytes |
|---|---|---|
| 2 | 2,339 B | 2,435 B |
| 3 | 3,492 B | 3,588 B |
| 5 | 5,798 B | 5,894 B |
| 7 | 8,104 B | 8,200 B |

### 3.2 Per-spend overhead

The spend-side overhead above baseline FCMP++ + PQC-auth is
approximately constant with N (the `pqc_auth` blob scales with M of
scheme_id=2, not with N for per-output data). The main spend-side cost
is the canonical `MultisigKeyContainer` serialized into
`pqc_auths[i].hybrid_public_key`, which is approximately:

| Component | Size |
|---|---|
| Version + n_total + m_required | 3 B |
| Hybrid sign pubkeys (N × 1984 B) | 1984 × N B |
| Spend-auth pubkeys (N × 32 B) | 32 × N B |
| **Total** | **3 + 2016 × N B** |

| N | Container size |
|---|---|
| 2 | 4,035 B |
| 3 | 6,051 B |
| 5 | 10,083 B |
| 7 | 14,115 B |

### 3.3 Network impact projections

At 5% multisig adoption with average N=3:

- Per-block size increase: ~0.5-1% (dominated by baseline FCMP++)
- Wallet scanning cost: negligible (1 KEM decap per candidate per
  participant; not N-fold)
- Node state cost: linear in adoption; multisig outputs stored with same
  structure as single-sig

At 25% multisig adoption with average N=5:

- Per-block size increase: ~3-5%
- Storage: tx_extra dominant for multisig outputs; chain-anchored
  registry (V3.3) could cut this 10x

### 3.4 Address size

Addresses are file-based (§6). Typical sizes:

| N | Bech32m chars | File size |
|---|---|---|
| 2 | ~10,260 | ~10 KB |
| 3 | ~15,380 | ~15 KB |
| 5 | ~25,620 | ~26 KB |
| 7 | ~35,860 | ~36 KB |

Too large for QR codes; file transfer is mandatory. Fingerprint
(§6.3) is the human-verifiable handle (3 parallel representations).

---

## 4. Attack Catalog

### 4.1 Summary

All attacks enumerated in the threat model (spec §3) plus those raised
in three rounds of wargaming. Each attack lists the adversary, the
attack, and the mitigation's location in v1.1.

### 4.2 Attack matrix

| # | Attack | Adversary | Mitigation | Spec §ref |
|---|---|---|---|---|
| A01 | Unilateral spend | Single group member | M-of-N consensus; verify_multisig | §14.1 |
| A02 | Recipient redirect via tampered construction | Proposer | Deterministic construction + I1 verification | §9.2, §2.7 |
| A03 | Wrong-prover key image attack | Prover | I5 signer verification using persisted N pubkeys | §11.3, §2.7 |
| A04 | Tampered tx at assembly | Assembler | I6 tx_hash commitment in SignatureShare | §11.5, §2.7 |
| A05 | FCMP++ proof substitution | Prover | I3 FCMP++ proof binds to independently-computed payload | §11.3, §2.7 |
| A06 | BP+ randomness manipulation | Prover | I4 deterministic BP+ derivation from intent | §10.2, §2.7 |
| A07 | Scheme downgrade (scheme_id=2 output spent as =1) | Spender | Leaf hash + size check; wired expected_scheme_id | §7.5 |
| A08 | Key substitution within group | Group member | verify_multisig Check 8 (key uniqueness) | §3.4 |
| A09 | Signer index manipulation | Signer | verify_multisig Checks 6-7 | §3.4 |
| A10 | Replay across groups | External | group_id in canonical signing payload | §3.4 |
| A11 | Replay within group (same intent) | External | intent_id + tx_counter + expires_at + kem_randomness_seed | §3.4 |
| A12 | Griefing via malformed output | Malicious sender | §7.6 per-sender griefing scores + hard caps; §8.3 receive-time validation (I7) | §7.6, §8.3 |
| A13 | Time-bomb output (decaps but binds wrong Y) | Malicious sender | §8.3 receive-time validation catches before balance | §8.3, §2.7 |
| A14 | Address file substitution | Attacker with filesystem access | §6.3 address provenance + dual confirmation on fingerprint change | §6.3 |
| A15 | Social-engineering attack on multisig address | Attacker intercepting address exchange | §6.3 three-representation fingerprint UX + §6.4 mandatory verification | §6.3, §6.4 |
| A16 | Relay single-operator centralization | Single operator running multiple relays | §12.4 signed relay directory + operator IDs in heartbeats | §12.4 |
| A17 | Relay censorship | Relay operator | Multi-relay (≥3 distinct operators) + heartbeat detection | §12.4, §13.3 |
| A18 | Conflicting simultaneous intents (grindable tiebreak) | Malicious proposer | ProverReceipt with monotonic local_counter | §10.5 |
| A19 | Prover equivocation (different proofs to different signers) | Malicious prover | EquivocationProof (§12.2.4) + I6 commitment agreement | §12.2.4, §11.5 |
| A20 | Prover receipt equivocation (inconsistent counters) | Malicious prover | Monotonic local_counter in ProverReceipt | §10.5 |
| A21 | Forged CounterProof advancing to arbitrary tx | Attacker | §13.4 strengthened verification (exact input/output match) | §13.4 |
| A22 | Loose CounterProof match causing false advancement | Attacker | §13.4 exact consumed_inputs matching | §13.4 |
| A23 | Simple-mode shared-secret compromise | Malicious setup participant | §5.2 DKG mandatory; simple-mode excluded from release builds | §5.2 |
| A24 | Intent spam via proposer_index multi-indexing | Malicious member | §11.7 rate limit by signing pubkey, not index | §11.7 |
| A25 | Unknown spend_auth_version confusion | Malicious sender | §8.2 silent skip; no error emission | §8.2 |
| A26 | Silent scheme reinterpretation across versions | Future-version attack | §5.3 spend_auth_version in group_id; §15.5 no implicit upgrades | §5.3, §15.5 |
| A27 | Filesystem metadata leakage via filenames | Forensic / accidental exposure | §12.6 opaque filenames + encrypted manifest | §12.6 |
| A28 | Scanner CPU exhaustion via sustained griefing | Sender with budget | §7.6 7-day cooldowns + per-sender scores + 10k cap | §7.6 |
| A29 | Honest-signer invariant bypass via flag | Malicious or coerced signer | §2.7 no unsafe flags in supported builds; mechanical enforcement | §2.7 |
| A30 | State divergence unnoticed | Network partition | §9.3 chain_state_fingerprint + I2 | §9.3 |
| A31 | Rotation rule grinding to bias prover assignment | Sender | Accepted bounded risk; grinding cost scales with bias; cryptographer review target | §11.1, §7 (this doc) |
| A32 | Compromise of group's enduring KEM keys | Long-lived attacker | Out-of-scope for V3.1; mitigated by V3.2 rotation protocol | §3.2 |
| A33 | Permanent participant key loss | Normal attrition | Accepted 1/N loss; §5.4 mandatory acknowledgment; V4 FROST SAL fixes | §5.4, §11.6 |

### 4.3 Attacks added or strengthened in v1.1

Attacks that are new in v1.1 or received substantially stronger
mitigations compared to v1.0:

- **A13 Time-bomb output:** was theoretically possible in v1.0 because
  receive-time validation was partial. v1.1 §8.3 adds full structural
  validation before balance update.
- **A20 Prover receipt equivocation:** v1.0 ProverReceipt used timestamps
  which are grindable/forgeable. v1.1 uses monotonic `local_counter`
  which makes equivocation detectable.
- **A21, A22 CounterProof forgery / loose match:** v1.0 CounterProof
  verification was informal. v1.1 §13.4 formalizes exact-match rules,
  rescan trigger, and Veto pathway.
- **A29 Honest-signer invariant bypass:** v1.0 discussed invariants in
  scattered sections. v1.1 §2.7 makes them an authoritative list with
  mechanical enforcement requirements.
- **A30 State divergence:** v1.0 chain_state_fingerprint did not include
  prover assignments. v1.1 includes them.
- **A31 Rotation rule grinding:** v1.0 rotation rule used
  consensus-assigned post-inclusion data which was non-sender-computable.
  v1.1 uses `tx_secret_key_hash` which is sender-computable; grinding
  cost now formalizable (cryptographer review target §7).

---

## 5. Wargame Round Summaries

### 5.1 Round 1 (against split governance + receiving drafts)

Primary findings:

- Address file substitution between exchange and send was not bounded;
  led to §6.3 provenance tracking with dual confirmation
- Tiebreaker was hash-based and grindable; led to ProverReceipt design
- Rate limit was keyed on proposer_index (bypassable via multi-indexing);
  led to signing-pubkey-keyed limit in §11.7
- Relay directory was ambient ("use any 3 relays"); led to signed relay
  directory with operator identifiers in §12.4
- Missing 1/N loss acknowledgment at setup; led to §5.4 gate

### 5.2 Round 2 (against consolidated v1.0)

Primary findings:

- Scanner resource bounds were unspecified under sustained griefing;
  led to §7.6 per-sender griefing scores, 7-day cooldowns, 10k hard cap
- BP+ randomness source ambiguous (who generates, how verified); led
  to §10.2 deterministic derivation from intent
- File transport filenames leaked metadata; led to §12.6 opaque names
  + encrypted manifest
- Honest-signer invariants scattered across sections; led to §2.7
  authoritative list with mechanical enforcement
- CounterProof verification informal; partial path to §13.4

### 5.3 Round 3 (against v1.0 with R1+R2 fixes)

Primary findings:

- **FATAL:** prover-assignment verification in §11.3 referenced
  `group.kem_shared_secrets` (all N shared secrets), which is
  cryptographically impossible for any single participant. Verification
  was non-implementable.
- Receive-time validation only checked "did it decap," not "does O bind
  to the correct assigned prover." Sender could publish time-bomb
  outputs that pass scan but fail spend.
- ProverReceipt used timestamps, which prover could grind. Monotonic
  counter fixes equivocation detection.
- CounterProof could be forged by anyone with on-chain tx knowledge —
  no advancement lineage verification.
- Rotation rule used consensus-assigned data unavailable to sender at
  construction time, so sender couldn't set `O = Y_assigned` correctly.

**Resolution:** v1.1 adopts Solution C (independent per-participant
spend-auth secrets with all N pubkeys published in tx_extra tag 0x0A),
sender-computable rotation rule using `tx_secret_key_hash`, full
§8.3 receive-time validation, monotonic ProverReceipt counter, and
formalized §13.4 CounterProof verification.

### 5.4 Round 4 (planned, against v1.1)

Target focus:

- Attacks on the Solution C mechanism (grinding on
  `tx_secret_key_hash`, forward-privacy leakage via published pubkeys)
- Attacks on the §2.7 invariant enforcement (bypass via
  implementation bug, side-channel)
- Attacks exploiting the unknown-version silent-skip behavior
- Attacks on the relay directory signing process
- DKG ceremony failure modes

---

## 6. Rationale for Deferring Full Rotation to V3.2

Full rotation is the single largest surface area of protocol design
still pending. The rationale for explicitly deferring it, rather than
rushing it into V3.1, is **not scope protection but design maturity.**

A complete rotation protocol must handle:

1. **Individual participant key rotation** (one member rotates without
   changing group identity)
2. **Full group rotation** (all members rotate; produces new `group_id`)
3. **Spend-auth scheme upgrade** (move from `spend_auth_version=0x01`
   classical to `0x02` PQC when V4 FROST SAL ships)
4. **Migration transactions** consuming old outputs, producing new
5. **Race conditions during rotation windows** (in-flight spends during
   rotation; recovery on rotation abort)
6. **Privacy considerations on migration txs** (migration signals group
   activity in a distinct pattern; needs padding)
7. **Key escrow as mitigation for 1/N loss** (threshold-split backup
   keys to permit recovery of one participant's loss)

Each of these has failure modes that will surface primarily when real
users run the protocol against real threats. A rushed pre-launch rotation
design would:

- Freeze specific design choices before users have tested them
- Commit a byte format in `TX_EXTRA_TAG_MULTISIG_MIGRATION (0x08)` that
  later proves suboptimal
- Lock in a specific rotation-window timing that produces liveness
  failures in practice
- Pick a specific key-escrow topology before seeing how groups actually
  form and manage risk

V3.1 instead ships:

- **Reserved namespace** (spend_auth_version byte, tag 0x08, message
  0x0A) so that V3.2 can slot in cleanly
- **Forward-compatible primitives** (KDF labels per version; §5.3
  group_id binds version; §15.5 no implicit upgrades) so that rotation
  semantics remain unambiguous when V3.2 arrives
- **An explicit public commitment** that rotation will surface flaws
  through actual use, and V3.2 will address them rather than predict them

This commits the project to shipping V3.1 as a fully functional multisig
with documented 1/N loss limitation, learning from real deployments, and
then rolling out V3.2 with rotation once operational patterns are
established. It is the same principle applied to the V4 FROST SAL
timeline: wait for NIST standardization of the primitive rather than
ship speculative cryptography.

This is not optional scope protection. It is the "get it right, not get
it now" design principle (spec §2 principle 5) applied to the most
complex deferred feature.

---

## 7. Cryptographer Review Targets

V3.1 contains four distinct cryptographic concerns that warrant formal
review by an external cryptographer. These are not asking the
cryptographer to audit all of V3.1; they are asking for targeted
analysis on each of four specific questions.

### 7.1 Review target 1: KDF domain separation (§7.2)

**Question:** is the domain separation between `"shekyl-v31-hybrid-sign"`,
`"shekyl-v31-classical-spend"`, and `"shekyl-v31-view-tag"` sufficient
to ensure that knowledge of one derived value provides no information
about another?

**Specific concern:** standard HKDF analysis gives separation for
distinct info strings. Verify this applies under our specific KEM shared
secret input. Confirm labels are long enough and unambiguous enough to
rule out any collision under adversarial input.

**Deliverable:** written affirmation that under standard HKDF assumptions,
the three derivations are computationally independent, AND that
`"shekyl-v4-pqc-spend"` (reserved label for future PQC spend-auth) does
not collide with V3.1 labels.

### 7.2 Review target 2: KDF independence and spend-auth derivation (§7.1, §7.2)

**Question:** the per-output classical spend-auth secret `y_i` is derived
by `HKDF(ss_i, "shekyl-v31-classical-spend") → y_i`, and then `Y_i = y_i * G`.
Is this derivation path sound for use as a Schnorr/Ed25519 spend-auth
key in the FCMP++ proof?

**Specific concern:** the FCMP++ proving relation requires certain
distributional properties of the spend-auth keypair. Verify that
HKDF-derived output, interpreted as an Ed25519 scalar, satisfies
these properties. Address the "bit-clamping" question (Ed25519 typically
clamps bits 0, 1, 2, 254, 255 of the scalar) and whether our derivation
must clamp explicitly.

**Deliverable:** explicit statement of scalar derivation procedure
(clamp vs. don't clamp, and why) that is sound for FCMP++ prover input.

### 7.3 Review target 3: FCMP++ binding to Y_prover (§11.3, §11.5)

**Question:** when the FCMP++ proof is verified against
`persisted.output_pubkey` (which equals `Y_assigned` by construction and
is verified to do so at receive-time), does the FCMP++ proof actually
bind to `Y_assigned` specifically? Or could a malicious prover, possessing
some other `y'` with the same relation to the curve tree, produce a
proof that verifies against `Y_assigned` without knowing `y_assigned`
specifically?

**Specific concern:** the FCMP++ proof of "spending authority for leaf
hash H" is standard, but whether it strictly binds to the specific
Ed25519 keypair `(y, Y=yG)` that derived `O = Y` — versus any keypair
whose pubkey happens to equal `O` — needs explicit verification.

**Deliverable:** confirmation that FCMP++ prover-knowledge of `y` such
that `Y=yG=O` is required; no alternate witness produces a valid proof.

### 7.4 Review target 4: Rotation-rule grindability (§11.1)

**Question:** a sender can iterate `tx_secret_key` values to bias
`rotating_prover_index()`. What is the concrete cost to achieve
specific biases? Specifically:

- To bias one output's prover to a specific participant: ~N expected tries
- To bias all k outputs in a tx to one specific participant: ~N^k tries
- To achieve a target bias distribution (e.g., 80% to participant 2):
  what's the analysis?

**Specific concern:** the rotation rule is `first_byte(H(...)) mod N`.
The first byte of a cryptographic hash has negligible bias, so mod N is
approximately uniform. But the sender iterating over `tx_secret_key`
effectively grinds a rejection sampler — we need a formal bound on how
cheaply a sender can bias assignments, and whether any variant of the
formulation (e.g., `first_two_bytes` + rejection sampling) gives better
uniformity guarantees.

**Deliverable:** explicit grinding-cost analysis; recommendation on
whether to harden the rule further; confirmation that accepted bound is
appropriate for V3.1's threat model (sender-side griefing is bounded by
fee cost, which bounds grinding budget in practice).

### 7.5 Out of review scope (for clarity)

- Full protocol correctness (reviewer round 4 covers adversarial
  protocol-level attacks)
- Implementation correctness (covered by test vectors + fuzzing +
  interop tests in §16.8-16.9)
- Transport-layer cryptography (standard ChaCha20-Poly1305 AEAD with
  per-message key derivation; no novel construction)
- DKG ceremony correctness (reuses existing `dkg-pedpop` infrastructure,
  already reviewed)

### 7.6 Timeline

Cryptographer review is Phase 6 of the rollout (§16.10) and is
explicitly NOT a 1-2-hour task. Expect 2-4 weeks of engagement for
these four targets: discovery, formal analysis, written report, possible
iteration on spec language if findings require adjustment.

---

## 8. Open Questions and Future Work

### 8.1 V3.2 candidates

- Full rotation protocol (§6 above)
- Key escrow for 1/N loss mitigation
- Threshold-signed relay directory updates (remove GitHub-release
  trust root)

### 8.2 V3.3 candidates

- Chain-anchored group registry (reduce ~10-36 KB addresses to ~100 B)
- Traffic padding for transport privacy
- Encrypted sender_index in envelopes (currently cleartext)

### 8.3 V4 integration

- FROST SAL integration via `spend_auth_version = 0x02`
- Migration protocol from V3.1 classical spend-auth to V4 threshold
- Removal of rotating-prover role (threshold proving replaces it)
- Elimination of 1/N permanent-loss limitation

### 8.4 Research questions

- **Post-quantum KEM hybrid transitions:** when ML-KEM is eventually
  replaced (likely by a successor in NIST PQC Round 5+), how do we
  migrate existing groups' enduring KEM keys? Design probably resembles
  the V3.2 rotation protocol applied to KEM-only.
- **Optimal N for operational multisig:** wargaming and operational
  experience will tell us whether N=3 or N=5 is the typical shape.
  Current cap at 7 is consensus-imposed; no indication it needs raising.
- **Privacy-preserving group state summaries:** currently
  `GroupStateSummary` (message 0x08) is defined structurally but not
  fully analyzed for information leakage. Round 4 review target.

### 8.5 Documentation follow-up

- Migrate old `PQC_MULTISIG.md` to deprecation pointer after v1.1 merges
- Remove split governance/receiving drafts from repo
- Add `MULTISIG_OPERATIONS.md` for end-user guidance on group setup,
  backup practices, 1/N loss operational plans
- Generate canonical test vectors (spec §17) once reference Rust
  implementation stabilizes

---

*End of analysis companion. See `PQC_MULTISIG.md` v1.1 for the
normative spec.*
