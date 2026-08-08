# Wallet Message Signing (A2 / rewrite-plan 2c residue) — Design Round

**Status: ROUND 0 OPEN (2026-08-08).** Poses SM-DQ-1…SM-DQ-6. Nothing here
is ratified; the signature format freezes the moment it ships (a signature
issued on day one must verify forever), so every fork below resolves
before implementation starts.

**Scope.** The last unwired 2c method pair:
`Engine::sign_message(msg)` / `Engine::verify_message(msg, sig, address)`
([`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) Phase 2 target list),
projected as the RESERVED `sign_message` / `verify_message` RPC methods
(error band `-29800..-29899`, [`wallet_rpc.yaml`](../api/wallet_rpc.yaml))
and the stubbed CLI `sign` / `verify` commands. The rewrite plan parked
this pair with the annotation "own hybrid-key design decision"
([`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §rewrite row 2c);
this round is that decision.

**What the feature is for.** A transferable attestation binding a message
to a Shekyl address: "the holder of this address's keys signed these
bytes." Lineage use cases: proving address ownership to a counterparty
(exchange, pool, dispute), signing a statement from a treasury address.
It is user-facing surface (rules 80/81 apply to its errors and its size).

---

## §1 Grounded inventory (verified at source, 2026-08-08, dev 2ea0710a1)

1. **Address v1 carries no post-quantum *signature* anchor.** The
   classical segment is `version || spend_pk || view_pk || ek_bind_tag`
   (Ed25519 keys); the two PQC segments carry an **ML-KEM-768
   encapsulation key** (1184 B) — an *encryption* key, bound to the
   classical segment by `ek_bind_tag = cSHAKE256("shekyl/ek-bind-v1",
   ml_kem_ek)[..16]` (`shekyl-address/src/address.rs`). There is no
   ML-DSA verification key, and no commitment to one, anywhere in the
   address.
2. **The wallet holds no wallet-level ML-DSA identity.** The secret
   inventory is `spend_sk`, `view_sk`, `ml_kem_dk`
   (`shekyl-engine-file/src/secrets_transitional.rs`). ML-DSA keys exist
   only per-output, derived from `combined_ss` at spend time
   (`shekyl-crypto-pq/src/derivation.rs`).
3. **The machinery to mint one deterministically exists.**
   `derivation.rs::keygen_from_seed` derives a domain-separated
   ML-DSA-65 keypair from a seed and index; a wallet-level identity
   under a fresh domain string is mnemonic-recoverable by construction.
4. **Hybrid signature primitives exist with versioned canonical
   encodings.** `HybridEd25519MlDsa` sign/verify, `HYBRID_KEY_VERSION` /
   `HYBRID_SIG_VERSION` / scheme-id bytes, length-checked
   `from_canonical_bytes` (`shekyl-crypto-pq/src/signature.rs`).
5. **Sizes.** Ed25519 signature 64 B. ML-DSA-65 signature 3309 B,
   verification key 1952 B. A hybrid signature carrying its vk is
   ~5.3 KB raw, ~7.2 KB base64 — three orders of magnitude larger than
   the 64 B classical form users paste today.

## §2 The structural fact the round turns on

A **transferable** signature is verified against the address alone, so it
is at most as strong as the address's signature anchors — and address v1
anchors only Ed25519 (§1.1). No signature format choice can make a
transferable proof quantum-resistant against address v1: a quantum
forger who breaks the spend key can issue fresh signatures of any format
we define, because the address cannot distinguish our PQ key from theirs.

The inverse also holds and is easy to miss: the ML-KEM ek **is** a
PQ-secure anchor for an **interactive** proof (verifier encapsulates to
the address, wallet proves decapsulation). Interactivity, not signature
composition, is where address-v1 PQ ownership proof actually lives.

Every fork below is downstream of this fact.

## §3 Design questions

### SM-DQ-1 — Signature composition (the anchor question)

- **(a) Classical-only.** Ed25519 over the domain-separated preimage,
  64 B, wallet2-parity shape. Honest about §2, minimal size. But it
  mints a *new, frozen, pure-classical attestation surface* on a chain
  whose first mission commitment is hybrid PQC from genesis — and every
  signature issued before a future upgrade is classical forever.
- **(b) Hybrid, vk-certified — LEAD.** The signature carries a
  seed-derived wallet-level ML-DSA-65 vk (§1.3); the Ed25519 half signs
  `preimage || ml_dsa_vk` (the address-anchored key certifies the PQ
  key); the ML-DSA half signs the same preimage. Properties, stated
  without overselling:
  - Against a classical adversary: strictly ≥ (a) — both halves must
    verify.
  - Against a future quantum adversary: *fresh* forgeries remain
    possible (§2, inherent to address v1) — but signatures issued
    **before** the break retain PQ non-repudiation for any verifier who
    archived them (their embedded vk stays unforgeable), and the format
    survives an address-v2 PQ anchor without redefinition: v2 turns the
    embedded vk from Ed25519-certified into address-committed.
  - Cost: ~7.2 KB armored strings (§1.5) — a paste-into-a-form UX, not
    a read-over-the-phone one.
- **(c) Defer the pair to address v2.** No new frozen format until the
  address can anchor it. Rejects A2 rather than deciding it; blocks a
  parity item on an unscheduled, genesis-adjacent format change.

The lead is (b): (a)'s only advantage is size, and size is a UX cost
while (a)'s deficit is a mission-hierarchy cost (priority 1 outranks
convenience); (c) converts a bounded decision into an unbounded
dependency. The round should still price (b)'s wire format honestly —
SM-DQ-5.

### SM-DQ-2 — Interactive KEM ownership proof (separate surface)

§2's inverse: `ml_kem_ek` supports a PQ-secure *interactive*
challenge-response today. That is a different API contract
(challenge/response, non-transferable), a different consumer (live
counterparty vs. archived attestation), and none of wallet2's parity
surface. Disposition to ratify: **rejected-now, rule 21** — reopen when
a consumer surface needs live PQ ownership proof (e.g. an exchange
integration spec) or when address v2 lands and the comparison changes.
Not a blocker for SM-DQ-1; recorded so the round shows it was seen.

### SM-DQ-3 — Preimage and domain separation

Proposed preimage (rule 30 — no naked hashes, no cross-surface reuse):

```
preimage = H(domain || version || network_id || mode ||
             classical_segment || H(message))
```

- `domain`: a fresh string in the house style (`"shekyl/msg-sign-v1"`);
  collision-checked against the derivation/binding domains in §1.
- `mode`: 1 byte — `0x01` spend-tier (this round's only mode);
  view-tier and future modes append, never renumber.
- Address binding: the **full classical segment** (version + spend +
  view + ek_bind_tag) so a signature cannot be transplanted between
  addresses sharing a spend key, and the ek binding rides the preimage.
  Fork to settle: full canonical address string instead? (Network
  segregation is already explicit via `network_id`; the segment is the
  byte-stable form.)
- `H(message)` not raw message: fixed-size preimage, no
  length-extension shape, streaming-friendly for large messages. House
  hash per rule 30 alignment (Blake2b-512 is the derivation-side
  precedent, cSHAKE256 the binding-side; pick one and pin it).

### SM-DQ-4 — The wallet-level ML-DSA identity

New domain-separated derivation from the wallet seed (fresh domain
string, reserved index) via §1.3's `keygen_from_seed`. Pins to ratify:
mnemonic-recoverable (no new backup material); never reused by any
other surface (per-output keys stay per-output; multisig identities
stay theirs); derived on demand and zeroized (rules 35/36) rather than
persisted — the wallet file schema does not change.

### SM-DQ-5 — Wire format

Versioned, armored, append-only:
`ShekylMsgSigV1` + base64(canonical bytes), canonical bytes being a
length-checked layout in the §1.4 house style (version, scheme,
mode, vk, ed25519 sig, ml_dsa sig). Reject-don't-truncate on decode,
explicit DoS ceiling (the decoder sees attacker-supplied strings via
`verify_message`). The ~7.2 KB size is stated in user-facing docs, not
hidden.

### SM-DQ-6 — API / RPC / CLI contract

- `Engine::sign_message` needs the open wallet (secrets). But
  **verification needs no secrets**: `verify_message` should be a pure
  function (crypto crate), callable by the RPC *without an open wallet*
  and by the CLI offline. Contract question to ratify: does RPC
  `verify_message` require an open wallet session (tenant model) or is
  it a session-less method? Lead: session-less — refusing to verify
  because no wallet is open is a rule-82 lie about a public operation.
- Errors in the reserved `-29800..-29899` band: malformed signature
  string vs. well-formed-but-not-verifying are different codes (the
  `get_transfer_by_id` precedent: formatting problems are `-32602`-class,
  semantic failure is its own honest code).
- Idempotent, deterministic signatures? ML-DSA-65 signing is
  randomized by default ("hedged"); deterministic mode exists. Fork:
  hedged (side-channel margin, fips204 default) vs. deterministic
  (reproducible outputs). Lead: hedged — reproducibility of the
  *signature bytes* is not a contract anyone needs, and hedging is the
  conservative side-channel posture.

## §4 Pre-committed test obligations (whatever SM-DQ-1 resolves to)

- Pinned KATs for preimage construction and full sign/verify vectors
  (rule 30: fixed seed → fixed vk → pinned signature bytes under
  deterministic test mode, plus verify-side vectors that must never
  rot).
- Tamper battery: every field of the armored format flipped
  independently → reject (version, scheme, mode, vk, each half,
  network, address binding, message).
- Cross-half battery: classical-valid/PQ-invalid and the inverse both
  reject (the hybrid contract is AND, never OR — §1.4's tx precedent).
- Decode DoS: oversized strings, truncations, non-base64 — bounded cost
  refusals.
- Round-trip through RPC + CLI including the no-open-wallet verify path
  (SM-DQ-6).

## §5 Proposed PR decomposition

- **PR-SM-1** — crypto + engine: preimage/domain, wallet-level identity
  derivation, sign/verify functions, armored codec, KATs + batteries.
- **PR-SM-2** — projection: RPC methods (band allocation), CLI
  un-stubbing (parity-matrix rows), OpenAPI, user-facing docs
  (including the size statement), FOLLOWUPS/INDEX closure of the 2c
  residue.

Small enough to merge if PR-SM-1 lands clean; split pre-committed only
if review load argues for it.
