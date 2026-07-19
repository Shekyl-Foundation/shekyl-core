# Archival bond — gate 4 (join-Market + bond-post wire)

**Status:** **Round 1 base (2026-06-07).** Consensus-balance custody; balance-equation
`bond_credit` / `bond_debit`; conservation law; `== bond_floor`; `Unbond`; `E_join+1`.
Numeric cluster pinned in [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md);
slash trigger interface pinned in [`ARCHIVAL_RETENTION_GATE2.md`](../completed/ARCHIVAL_RETENTION_GATE2.md) §6.

**Scope:** Consensus objects and vin wire for **bond posture** — **join-Market**, **re-bond**,
**clean unbond** (collateral return), holdings updates — **distinct** from reward **mint**
(emission leg).

**Authority chain:**

| Doc | Role |
|-----|------|
| [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) | FSM edges; R1 closed (join ≠ first mint) |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Consumer of bond record; mint + dedup only |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | `Market` membership; `R_market` / `Σwork` reads |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | join-Market timing; §2.5 bond-funding hygiene |

**Out of scope here (interface only):** retention-proof construction (gate 2); emission
economics (gate 1); admission principal economics (gate 7); wallet FSM implementation.

---

## 1. Why join-Market is a separate event from first paying mint

### 1.1 Five functions — two instants

| Function | Gates | Active from | join-Market | First paying mint |
|----------|-------|-------------|-------------|-------------------|
| Locked bond posted | Ledger admission | join | yes | — |
| Gate-2 writes `(P,s,E)` retention bits | `P` serves | join | yes | — |
| `P ∈ Market` | `R_market` / `Σwork` | `E ≥ E_join + 1` | yes | — |
| Claim eligibility | mintable epochs | `E ≥ E_join + 1` | yes | — |
| Slash teeth | bond collateral | join | yes | — |
| Dedup + mint | `claimed_settlement_epochs` | first pay | empty at join | yes |

Rows 1–4 and slash fire at **join-Market**. Mint and dedup mutation fire at **first paying
emission** (earliest claimable epoch **`E_join + 1`** — §2.2). Work in partial epoch
`E_join` is **forfeited** (deterministic boundary; no gate-2 coupling).

### 1.2 Settlement lag makes bundling impossible

Emission §4.5: paying emissions for epoch `E` cite `Σwork(E)` finalized at **E-close**,
typically in **`E+1` or later**. `Σwork(E)` counts only `P' ∈ Market` at E-close (emission
§4.2; archival state invariant 2).

If `ArchivalBondRecord` is created only at first paying mint (≥ `E+1`), then at E-close
`P ∉ Market` → epoch `E` was never counted → nothing valid to claim. Retroactive Market
entry would mutate finalized `R_market(s,E)` — **forbidden**.

**Conclusion:** bond record creation (**join-Market**) must precede the first **paying**
mint by at least one settlement-epoch lag. This is consensus ordering, not a privacy
preference. See [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) R1.

### 1.3 Anti-replica-flooding

`Market` entry without bonded collateral would let attackers register unbounded fake `P`
replicas, crater `R_market` scarcity, and drive honest reward toward zero. Bond at join
makes each counted replica cost `ARCHIVAL_BOND_FLOOR` (sim pin) and real storage (8c).
**Pre-mint bond job = `R_market` integrity**, not only post-hoc slash.

### 1.4 No pre-join consensus footprint

Gate-2 **does not write** `serve_credit_bit(P, shard, E)` before join-Market. Bits may not
accrue for `P` without a bond record — closes state-bloat and grief vectors for
unbonded announced `P`.

---

## 2. join-Market event (genesis pin)

### 2.1 Definition

**join-Market** is the first on-chain event that:

1. Posts locked bond: `bonded_total_atomic == bond_floor(holdings)` (§3.2, §4.1).
2. Creates `ArchivalBondRecord` keyed by `P_canonical_id` (emission §6.1).
3. Initializes `claimed_settlement_epochs` **empty**.
4. Stamps `join_market_height` and `join_settlement_epoch` (`E_join`).
5. Sets `good_standing = true` (initial posture).
6. Admits `P` to **`Market`** from this height forward.

After join, gate-2 may write serve-credit bits for **`E ≥ E_join + 1`**; `P` is counted in
`R_market` / `Σwork` and may emit for those epochs subject to lag, `W`, and dedup.

### 2.2 `E_join` boundary (R1b — closed)

```text
E_join = settlement_epoch(join_market_height)
       = join_market_height / SETTLEMENT_EPOCH_BLOCKS    // integer division; emission §3

E_first = E_join + 1    // first settlement epoch counted and claimable
```

**Single `Market` predicate (consensus pin — G4-5):**

```text
P ∈ Market for settlement-epoch E  ⇔
  ArchivalBondRecord exists for P_id
  ∧ E ≥ E_join + 1
  ∧ good_through(P, E)              // evaluated at E-close; archival state §3.4
```

**Derived reads (same predicate — no §2.2 vs §4 split):**

```text
counted_in_R_market(P, shard, E)  ⇔  serve_credit_bit(P,s,E) ∧ (P ∈ Market for E)
claimable_epoch(E) in emission    ⇔  (P ∈ Market for E) ∧ dedup ∧ W ∧ … (emission §6.5)
```

**Partial epoch `E_join`:** join may land at any height within `E_join`. **No counting or
claims for `E_join`** — avoids coupling claimability to gate-2 challenge-close ordering
inside the epoch. Cost: at most one forfeited partial epoch. **No retroactive `E < E_join+1`
counting** (invariant 2).

**First paying mint:** earliest batch `[E_first, …]` = `[E_join + 1, …]`; emitted in
settlement epoch **`≥ E_join + 2`** for work finalized at `E_first` close (§4.5 lag), or
later within `W`.

### 2.3 Registration fusion (preserved meaning)

**Fusion** = no separate *registration transaction type* in the retired stake sense.
**Not fusion** = no on-chain anchor — join-Market **is** the registration **event**
(PHASE_2B §2.4). Off-chain announce + backing presentation still **precedes** join.

### 2.4 FSM coupling

| Wallet transition | On-chain event |
|-------------------|----------------|
| `AdmissionPending` → `Bonded` | join-Market confirm |
| First operator payout | First **paying** `txin_archival_reward_emission` in `Bonded` |
| `Bonded` → `AdmissionPending` (reorg) | join-Market block disconnected (§5) |
| `Slashed` → `Bonded` | Re-bond (§4.2) |
| `Exited` → collateral returned | **Unbond** after release cooldown (§4.3) |

"Joined but not yet paid" = `Bonded` with empty `claimed_settlement_epochs` — **not** a
fifth state.

**Exit vs bond (G4-1):** the **drain** (PHASE_2B §2.4) spends `P`'s ordinary
FCMP++ outputs only *(the "decorrelated" qualifier was retired 2026-07-16 as phantom under
FCMP++ — F-W10, gate-6 §12.9)*. **Bond collateral is a consensus balance**, not a spendable
UTXO — clean exit requires **`BondPostKind::Unbond`**, not drain.

**Release refund (gate-6):** the `Unbond` **transaction** is `P`-attributed and its refund
amount is publicly derivable — `bond_debit == bonded_total == bond_floor(holdings_current)` —
the record's **current** holdings being fully released (distinct from the vin's post-connect
`holdings` field, which is empty on `Unbond`; §3.5 debit-path note). The refund itself enters
as **ordinary hidden vouts** CT-balanced against that public source term (§3.5 release fold):
no identifiable "refund output" exists on the wire. *(Corrected 2026-07-16 — gate-6 §2.4
method-note-5 re-walk: the earlier "P-attributed refund output" phrasing named an output no
observer can identify, and the "decorrelated-drain discipline applies" tail retired with
F-W10.)* FCMP++ tree membership is value-agnostic (the vouts mix normally).

---

## 3. Wire shape — `txin_archival_bond_post` (genesis lean)

### 3.1 Disposition

| Option | Verdict |
|--------|---------|
| **(a)** Zero-mint `txin_archival_reward_emission` | Rejected — conflates bond posture with mint wire |
| **(b)** Dedicated `txin_archival_bond_post` | **Genesis lean** — one vin for join + re-bond |

Emission leg handles **mint + dedup only**; bond posture changes use this vin.

### 3.2 Custody model — consensus balance (round-1 base)

The bond is **not** a UTXO and **not** a spend-lock on a UTXO. It is
**`bonded_total_atomic`** on `ArchivalBondRecord` — a divisible consensus-held balance keyed
by public `P_canonical_id`.

**Maintained invariant (per record):**

```text
bonded_total_atomic == bond_floor(holdings)    // equality, not ≥
```

Over-bonding buys nothing (slash is floor-or-whole per FOUNDATION §3.2) and would make the
cleartext bond term a per-`P` fingerprint. **Floor it; do not tune** (FOUNDATION §3.1).

**Funding inputs** to bond-post txs are still ordinary FCMP++ UTXOs; only the **bond
instrument** is non-UTXO.

#### Rejected UTXO framings (G4-2 — closed)

| Framing | Why rejected |
|---------|----------------|
| Attest UTXOs P controls, leave spendable | Slash-unsound — consensus cannot seize; P front-runs |
| Attest + consensus spend-lock via key-image blacklist | FCMP++ spends are membership-unlinkable; lock requires pre-revealed key images → early linkability, stranded (not burned) supply, no per-shard `FLOOR` decrement |

#### Balance-equation terms (replaces `BondAttestation`)

Bond posture changes ride the **standard RCT balance proof** (emission leg §7.1 step 8 —
same class as loud emission mint). Cleartext terms on the vin:

```text
Σ input_commitments = Σ output_commitments + fee + bond_credit − bond_debit
```

| Term | Class | Soundness bar |
|------|-------|----------------|
| `bond_credit` | **Sink** — removes value from circulation | **Below mint bar** — cannot inflate; inputs must cover credit (balance equation) |
| `bond_debit` | **Source** — returns bonded value to outputs | **At or below mint bar** — authorization is `bond_debit == bonded_total` (single scalar read), strictly less surface than emission mint (work/Σwork/budget recompute) |

Emission already ships a loud cleartext **source** term (mint) inflation-checked on the vin
(emission §5.5). Bonds need less than that.

**Allowed terms per `post_kind` (exactly one direction per tx):**

| `post_kind` | `bond_credit` | `bond_debit` | Notes |
|-------------|---------------|--------------|-------|
| `JoinMarket` | yes (`== bond_floor`) | no | Creates record |
| `Rebond` | yes (`== bond_floor(post) − bonded_total`; **0 legal**) | no | Restores standing after slash; credit = growth only (P2B-9 Pin 2) |
| `Unbond` | no | yes (`== bonded_total`) | After release cooldown |
| `HoldingsUpdate` add shard | yes (`+FLOOR`) | no | V3.0 |
| `HoldingsUpdate` drop shard | no | yes (`FLOOR`) | V3.0; per-shard cooldown (§4.4) |

**Forbidden:** `bond_credit` or `bond_debit` on `txin_archival_reward_emission`; both
directions in one bond-post tx; either term on a paying emission tx.

On connect: `bonded_total_atomic` and global `total_bonded_atomic` (§4.5) move in lockstep
with the cleartext term.

**Fee — RATIFIED (2026-07-19, maintainer; `V3_WALLET_DECISION_LOG.md` "P-lane fees").**
Every bond post — credit *and* debit paths, `Unbond` included — carries the **standard
weight-priced floor fee**; no fee-less bond-post class exists (zero-fee is `Malformed` at
submit, `DAEMON_SUBMIT_VERDICT.md`). The balance equation above already carries `fee`
uniformly and the §3.3 envelope already admits `txin_to_key` inputs on every `post_kind`,
so this is construction policy, not wire change: debit-path posts fund the fee with
FCMP++ fee inputs exactly as credit paths fund `bond_credit` (§7.3 of
ARCHIVAL_BOND_CONSTRUCTION.md — typed `P`-space pool: cover + earnings outputs, exit-fee
reserve, no fee knob). The debit term is **never** fee-diminished: `Unbond` outputs
receive the full released `bonded_total`; the fee closes through the fee inputs.

A bond-post transaction contains:

1. **Exactly one** `txin_archival_bond_post` (this spec).
2. **Zero or more** `txin_to_key` inputs (ordinary FCMP++ + key images).
3. **Forbidden:** reward mint fields; `txin_archival_reward_emission` in the same tx.

### 3.4 `txin_archival_bond_post` — logical fields

```text
ArchivalBondPostVin {
  P_pubkey:              HybridPublicKey,
  bond_spend_pk:         Option<HybridPublicKey>, // present iff post_kind == JoinMarket (commits the debit authorizer, §4.1)
  p_canonical_id:        [u8; 32],             // hint; verifier recomputes (emission §6.1)
  post_kind:             BondPostKind,         // §3.5
  holdings:              HoldingsDescriptor,   // POST-connect state (empty for full Unbond; §3.5 debit-path note)
  bonded_total_atomic:   u64,                  // == bond_floor(holdings): the post-connect record total (0 for full Unbond)
  bond_credit:           u64,                  // cleartext; 0 unless credit path (§3.2 table)
  bond_debit:            u64,                  // cleartext; 0 unless debit path (§3.2 table)
  pqc_auths:             [...],                // bond-vin auth: identity key on credit, bond_spend_pk on debit (gate-6 §9.6)
}

enum BondPostKind {
  JoinMarket,
  Rebond,
  Unbond,
  HoldingsUpdate,        // V3.0 wire; credit/debit directions §3.2
}
```

### 3.4.1 Byte layout (genesis pin)

Vin type tag **`5`** (`txin_archival_bond_post`). Varint discipline matches gate-2 §5.1.1 /
[`shekyl-curve-io`](../../rust/shekyl-curve-io). Reference implementation:
`shekyl-archival-retention::bond_wire`.

```text
u8                      vin_type = 5
varint                  hybrid_pubkey_len   (≤ 2048)
[hybrid_pubkey_len]     HybridPublicKey::to_canonical_bytes()   // P_pubkey (identity)
[32]                    p_canonical_id      (hint; verifier recomputes)
u8                      post_kind           (0=JoinMarket, 1=Rebond, 2=Unbond, 3=HoldingsUpdate)
// if post_kind == 0 (JoinMarket): the dedicated bond-spend key is committed into the record
varint                  bond_spend_pk_len   (≤ 2048)            // present iff post_kind == 0
[bond_spend_pk_len]     bond_spend_pk.to_canonical_bytes()      // present iff post_kind == 0
u8                      holdings_kind       (0=ShardSetCompact, 1=CompleteTree)
// if holdings_kind == 0:
varint                  shard_count         (≤ 4096)
repeat shard_count:
  varint                shard_id            // set: no duplicate id; order preserved (not canonicalized)
// if holdings_kind == 1: no shard list (sentinel only)
varint                  bonded_total_atomic
varint                  bond_credit
varint                  bond_debit
```

**The shard list is a set on the wire (ratified 2026-07-15).** A `ShardSetCompact`
holdings carries **no duplicate shard id** — a shard is a distinct retention
obligation, so `[7, 7]` (which would bond `2·FLOOR` for one shard) is invalid.
This is enforced at the **decode boundary** in both consensus decoders — the Rust
`bond_wire::ShardSet` newtype (parse-don't-validate: bound + duplicate-free at
construction, the only way to obtain a `ShardSet`) and the independent
`shekyl-wire` oracle — so an invalid set is unrepresentable past any decoder
rather than re-guarded per verify. **Insertion order is NOT canonicalized:** the
ids encode in the order given, so `[7, 42]` and `[42, 7]` are distinct valid
encodings of the same set (benign — holdings feed the signature preimage, so only
the signer produces either and only one connects). The encoding of any valid
(duplicate-free) holdings is **byte-identical** to the pre-`ShardSet` form; the
tightening rejects only duplicate-carrying byte strings, which no honest wallet
emits.

Hybrid spend authorization uses **transaction-level** `pqc_auths[]` aligned with `vin[]`
indices (not an on-vin signature blob). Preimage:

```text
sig_preimage = cSHAKE256(
  customization = "shekyl/archival-bond-post-v1",
  input         = tx_prefix_hash
                  || p_canonical_id
                  || post_kind_u8
                  || encode_bond_spend_commitment   // JoinMarket: bond_spend_pk canonical bytes; else empty
                  || encode_holdings_descriptor
                  || bonded_total_atomic_le64
                  || bond_credit_le64
                  || bond_debit_le64
)
```

`encode_holdings_descriptor` is the on-wire holdings section (`holdings_kind` byte plus
optional shard-id varint list). `encode_bond_spend_commitment` is `bond_spend_pk`'s canonical
bytes on the `JoinMarket` path and **empty** on every other `post_kind` — so the establishing
identity-key signature (below) binds the committed debit authorizer at creation, foreclosing a
key-swap at join. On-wire amount fields use varints; preimage uses fixed `le64`.

**Bond-vin authorizing key (GF-1, gate-6 §9.6).** The `pqc_auths[]` entry aligned with the bond
vin verifies against:

- **credit / identity-establishing paths** (`bond_debit == 0`: `JoinMarket`, `Rebond`,
  `HoldingsUpdate` add-shard) — the **identity key `P_pubkey`** (`= hybrid_sign_pk`). The funded
  value arrives via standard `txin_to_key` inputs (key images, self-authorizing); the bond-vin
  signature only proves control of `P_canonical_id`.
- **debit paths** (`bond_debit > 0`: `Unbond`, `HoldingsUpdate` drop-shard) — the record's
  committed **`bond_spend_pk`**, never `P_pubkey`.

The account identity key therefore **never authorizes a value-out**, preserving the Round-1
identity-only invariant (gate-6 §9.6 GF-1).

**JoinMarket path:** reject if `ArchivalBondRecord` already exists for `P_canonical_id`;
require the `bond_spend_pk` field present (`scheme_id = 1`) and **commit it into the new record**
(immutable debit authorizer, §4.1); `bond_credit == bond_floor(holdings)`; credit
`bonded_total_atomic` and `total_bonded_atomic`.

**Rebond path (reinstatement, not re-entry — P2B-9):** require existing record with an
**open bad interval** (`good_standing == false`, both slash severities); the vin's holdings
must be `ShardSetCompact`, **non-empty**, and a **superset of the record's current holdings**
(shedding stays `HoldingsUpdate`-drop's gated job — Pin 1); `bond_credit ==
bond_floor(post) − bonded_total == |added|·FLOOR`, **zero legal and common** (the landed
slash preserves floor-equality, so standing-only reinstatement carries no credit — Pin 2,
amending the earlier "restores `== bond_floor`" wording); interval-cap headroom
`bad_intervals.size() ≤ 254` (one slot reserved for the next slash + one for `Unbond`'s
clean close, so exit is always reachable — Pin 6); **close** the open bad interval
(`end_exclusive = E_rebond + 1`, F3 / Pin 3). Carried shards keep their add-epochs; added
shards take `E_rebond` (Pin 7).

**Unbond path (G4-1):** clean release of bonded balance when:

1. `P` has initiated exit (drain confirmed — the "decorrelated" qualifier was retired
   2026-07-16 as phantom under FCMP++, F-W10 / gate-6 §12.9) **or** is in `Exited` posture, and
2. **Release cooldown** elapsed: grace window past `P`'s last served settlement epoch
   (gate-4; **shorter than `W`**), **and**
3. **Slash settlement** reached the anchor: the slash scheduler's settled watermark
   (`archival_last_slash_epoch`) is `>=` `P`'s last-served anchor, so every epoch up to
   the anchor has been slash-processed on still-bonded collateral before the release
   verifies.

The two-part gate is load-bearing (ratified 2026-07-12). The cooldown alone leaves a
one-block race: the connect dispatch runs *before* the per-block slash fold
(`add_transaction` precedes `process_archival_slash_at_height` in `add_block`), so in
the first block past the anchor epoch's slash deadline an `Unbond` would exit the record
ahead of the fold that settles it — the settlement gate closes exactly that. Together they
guarantee: every epoch through the last serve is slash-settled while bonded (a
held-but-unserved failure at or before the last serve is already slashed); the epochs
*after* the last serve — at most the cooldown window, unserved by definition, earning
nothing — are **exit-forgiven by construction**, because slashability ends at the `Unbond`
connect and the refund is never clawed back.

On confirm: `bond_debit == bonded_total`; refund output(s) to `P`; zero
`bonded_total_atomic`; decrement `total_bonded_atomic`; append **clean interval-close** to
`bond_event_log` (F3) so `good_through(E)` stays true — **backlog emission still verifies
post-release** within `W`.

**Asymmetry (load-bearing):**

| Window | Duration | Governs |
|--------|----------|---------|
| Release cooldown | ~one grace window after last serve | When collateral may **Unbond** |
| Backlog claim (`W`) | `MAX_CLAIM_AGE_W` epochs | When reward epochs **forfeit** (E-3) |
| Retention commitment | `bond_duration(age)` per shard (below) | When a held shard may be **voluntarily dropped** |

Collateral return and reward mint are **independent value flows**.

**Retention-commitment horizon (sim L9/L10; decided 2026-06-11).** Each held shard carries a
minimum commitment of `bond_duration(age) = BOND_DURATION_BASE_EPOCHS · (1 +
BOND_DURATION_AGE_SCALE · age)` settlement epochs from acquisition (normalized shard age
`age ∈ [0,1]`; constants in [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §1,
shape pinned / numerics provisional). Before the horizon elapses, the shard is ineligible for
voluntary drop via `HoldingsUpdate` (V3.0 wire) or `Unbond`-with-remaining-holdings; slash and
full exit (`Unbond` of the entire record after release cooldown) are unaffected — duration
deters *shard-drop while staying*, not capital flight
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*L10 hardening* disposition and
reversion clause).

### 3.5 Verify order (consensus) — bond-post tx

1. Structural — tx type, single bond vin, `P_canonical_id` recomputation matches. On
   `JoinMarket`, `bond_spend_pk` field present and well-formed (`scheme_id = 1`); on every other
   `post_kind`, `bond_spend_pk` field **absent** (it lives in the record).
2. `post_kind` preconditions — join / re-bond / unbond / holdings-update paths.
3. **Term rigidity** — `bond_credit` / `bond_debit` match §3.2 allowed-terms table (one
   direction only).
4. **Floor equality** — `bonded_total_atomic == bond_floor(holdings)` on the vin's **post-connect**
   state (holdings is the *resulting* set — empty for full `Unbond`; see the debit-path note below).
5. **Bond-vin authorization (GF-1, gate-6 §9.6)** — the `pqc_auths[]` entry aligned with the
   bond vin verifies against the **dedicated bond-spend key on debit paths** and the **identity
   key on credit paths**:
   - `bond_debit > 0` (`Unbond`, `HoldingsUpdate` drop) → verify against the record's committed
     `bond_spend_pk`. The account identity key `P_pubkey` (`= hybrid_sign_pk`) **must not**
     authorize a debit (identity-only invariant).
   - `bond_debit == 0` (`JoinMarket`, `Rebond`, `HoldingsUpdate` add) → verify against
     `P_pubkey`; on `JoinMarket` this signature also binds the committed `bond_spend_pk` via the
     sig-preimage (§3.4.1).
6. **FCMP++ balance** — `Σ in = Σ out + fee + bond_credit − bond_debit`; **no emission mint**.
   When `bulletproofs_plus` is non-empty, layout must be canonical (exactly one aggregated
   proof, `1 ≤ V.size() ≤ BULLETPROOF_PLUS_MAX_OUTPUTS`); credit-only join may omit proofs.

**Debit-path vin semantics (`Unbond` / `HoldingsUpdate` drop) — RATIFIED (2026-07-12, maintainer, P2B-8).**
The vin's `holdings` and `bonded_total_atomic` are the **post-connect** state, so step 4's floor
equality reads uniformly across every path — `vin.bonded_total_atomic == bond_floor(vin.holdings)` is
the *resulting* record. (The §3.4 field comment and the §4.3 refund line are now disambiguated to
match — `holdings` there means the record's *current* set — so this note is a consolidated summary,
not an ambiguity patch.) Consequences:

- **`HoldingsUpdate` drop** carries the **reduced** holdings; the connect diffs it against the record's
  current set to identify the dropped shard (which is why the vin must carry the post-state, not the
  current set — there is no separate drop-shard field).
- **Full `Unbond`** carries **empty holdings** (`bond_floor(∅) = 0`, so `bonded_total_atomic = 0`). The
  `ShardSetCompactEmpty` rejection is a **credit / identity-path** check (`JoinMarket` / `Rebond` /
  add / drop-with-remaining hold ≥ 1 shard), **not** a full-`Unbond` check.
- **Debit amount:** `bond_debit == record.bonded_total(current) − vin.bonded_total_atomic` (= the full
  `record.bonded_total` for `Unbond`). §4.3's `bond_debit == bonded_total == bond_floor(holdings)`
  refers to the **record's current** holdings (the refund amount), *not* the vin's post-state field —
  so there is no contradiction with step 4.

Rust-native verify: `shekyl-archival-retention::bond_post` (rule 20). **Ratified by the maintainer;**
the current-set-echo alternative (which would need a separate drop-shard field) is declined.

On block connect for **JoinMarket:** create `ArchivalBondRecord` (§4.1); credit
`total_bonded_atomic`.

On block connect for **Unbond** (§4.3 "On confirm"; connect fold + pop twin landed
Rust-native, `shekyl-archival-retention::bond_connect` over
`shekyl_archival_unbond_connect` / `shekyl_archival_unbond_pop` — rule 20, P2B-8
implementation locus; **C++ dispatch wiring LANDED**: `add_transaction` Unbond arm →
`apply_archival_unbond` single writer, `m_archival_bond_unbond_log` pre-image
journal, `pop_block` → `revert_archival_unbonds_at_height`, verify dispatch in
`check_archival_bond_post_input` with the Q1/Q2 reverse-cursor anchors via
`archival_bond_last_served_epochs`):

1. Journal the record's **full pre-image** before mutating (the emission WS-2 §6.3
   shape) — the vin carries the *post*-state, so holdings are not reconstructible
   at pop without it.
2. Record → `Exited` shape: `bonded_total_atomic = 0`, `holdings` = compact-and-empty
   (the same exit shape the slash-to-zero path writes); the record **persists** for
   backlog claims until `W` lapses (`p_slot` burn is a later, separate step).
3. `total_bonded_atomic -= bond_debit` (§4.5 release row; `circulating` needs no
   explicit write — the refund enters as ordinary hidden vouts, CT-balanced by the
   `bond_debit` source term; §2.4). **Counter-threading obligation:** the fold
   returns the new total as an **absolute** post-value, so the dispatch must read
   the live counter immediately before *each* post (`get → fold → set`, the
   JoinMarket arm's shape) — a hoisted per-block read would compute every debit
   from the same block-start total and clobber all but the last write. The
   per-`P` pass does not cover this (different-`P` posts in one block are
   legitimate and share the counter).
4. Append the **clean interval-close** `[E_unbond, E_unbond)` to the interval log
   (F3, zero-length ⇒ `good_through`-inert — see §4.1's landed-representation note);
   backlog emission still verifies within `W`.

Pop twin (§5): restore the record from the journal pre-image byte-identically
(carries holdings and the interval log — the clean close vanishes with it) and
re-credit `total_bonded_atomic`; the fold validates the tip record is the connect's
product (Exited state + trailing clean close) so a journal desync is loud.
**Trailing-entry invariant (ratified 2026-07-12):** slashability ends at the
`Unbond` connect — the slash scheduler only challenges *currently held* shards
and an `Exited` record holds none — so nothing ever appends after the clean
close, and the trailing-clean-close check holds unconditionally. (The release
verify guarantees every epoch through the record's last-served anchor is
slash-settled *before* the connect; see §4.3's slash-settlement gate.)
`pop_block` still reverts slashes before the bond journal, but that ordering is
now a **defensive belt** — a same-block slash on a *different* record is
routine — not a correctness dependency on a post-close slash to the exiting
record. A future change that let an interval land after a clean close surfaces
as `MissingCleanClose`, loud. Connect
fold errors are FATAL at the call site, never a soft skip. Verify enforces the
interval-log codec cap (`IntervalLogFull`) so a tx the connect could not apply
never verifies — which makes `kMaxBadIntervals` a **genesis-frozen consensus
constant** (tx validity keys on it; static_assert-pinned against its Rust twin
`MAX_BOND_BAD_INTERVALS`).

**GF-1 debit authorization — LANDED (2026-07-13); the debit side is enabled.**
Step 5's selection is live in `check_archival_bond_post_input`, with the auth
key (`tx.pqc_auths[bond_index].hybrid_public_key`, whose signature over the
whole-tx payload `verify_transaction_pqc_auth` checks) pinned kind-dependently:
**credit paths → the identity key `P_pubkey`; debit paths → the record's
COMMITTED `bond_spend_pk`** — the shared debit authorizer both flip pins asked
for (`HoldingsUpdate`-drop rides the same selection when it lands). The wire
divergence is reconciled: the C++ `txin_archival_bond_post` (binary, boost, and
JSON serializers) carries the §9.11 JoinMarket-coupled field with the exact
canonical length enforced both directions, matching `shekyl-wire` and the
now-coupled Rust `bond_wire` codec (whose §3.4.1 `signature_preimage` binds the
key; the operative consensus binding also rides the tx prefix inside the pqc
payload). The v5 record (`ArchivalBondValue`, v4 rejected at decode —
datadir-reset posture) commits the key once at JoinMarket connect
(`put_archival_bond_record`, no-default parameter so no caller can silently
commit an empty authorizer). The reject→auth swap landed in one change, pinned
by the discriminating KATs
(`archival_bond_post.gf1_unbond_auth_discriminates_on_committed_key` + siblings):
the committed key accepts — Unbond verifies end-to-end — while the identity
key, a foreign key, and a record committing no key (pre-GF-1 shape) all reject
fail-closed, never an identity fallback.

**Coverage boundary (named, #302 review):** the selector's soundness rests on
two load-bearing preconditions **upstream and out of its scope** — the
vin↔auth **index mapping** (`pqc_auths[bond_index]` is the bond input's auth;
`pqc_auths.size() == vin.size()` is enforced at classification) and the
**signature verification itself** (`verify_transaction_pqc_auth` over the
whole-tx payload against that entry's key). The GF-1 check only pins *which*
key must be that authorizer. Any change to the pqc-auth indexing or payload
shape must re-check this seam; the `HoldingsUpdate`-drop slice inherits the
same preconditions when its `bond_debit > 0` rides this selection.

**Block-level bond-post pass (LANDED end-to-end):** at most **one bond-post vin
per `P_canonical_id` per block**, keyed on
`P` alone, **rejecting the block** — `bond_post_block_unique`
(`shekyl-archival-retention::bond_post`, over `shekyl_archival_bond_post_block_unique`;
the emission `(P,E)` pass's sibling, same decision-placement pin: C++ marshals the
block's ids, Rust decides). Per-tx verify runs against pre-block DB state, so
**every** same-`P` same-block pair passes it independently — JoinMarket+JoinMarket
(double `total_bonded_atomic` credit), Unbond+Unbond (double debit),
JoinMarket+Unbond, and every future `HoldingsUpdate` combination — and the §4.5
conservation audit is **not** a backstop (a double-credit doubles both sides of
`total_bonded == Σ_P bonded_P` consistently, so it passes on corrupt state).
Reject, not serialize: lifecycle transitions have no legitimate
multi-post-per-`P`-per-block use, and serializing would invite intra-block
ordering dependence (reopen per rule 21 only if a real use case emerges).

---

## 4. `ArchivalBondRecord` fields (gate-4 owned)

Amends emission §6.2 — emission **reads** this shape; gate 4 **writes** on bond-post and
slash paths.

```text
ArchivalBondRecord {
  P_pubkey:                  HybridPublicKey,
  bond_spend_pk:             HybridPublicKey,   // debit authorizer (GF-1); committed at JoinMarket, immutable
  holdings:                  HoldingsDescriptor,
  bonded_total_atomic:       u64,
  good_standing:             bool,
  join_market_height:        u64,       // block of JoinMarket bond-post
  join_settlement_epoch:     u64,       // E_join
  first_paying_emission_height: Option<u64>,  // set on first mint; None until then
  claimed_settlement_epochs: ClaimedEpochSet,  // emission §6.3; empty at join
  bond_event_log:            BondEventLog,     // slash / re-bond / unbond intervals (F3)
}
```

**Deprecated name:** `first_emission_height` → split into `join_market_height` +
`first_paying_emission_height`. Pre-genesis docs/code use new names only.

**`last_served_epoch` dropped (P2B-8 Q2, amended 2026-07-12).** The field's sole
consumer was the `Unbond` release cooldown (§4.3), and it is **derived, never
stored**: whole-record last-served = max over the record's current shards of the
per-shard reverse-cursor maxima over the serve-credit table's BE composite key
(P2B-8 Q1). A maintained field would only add pop-symmetry surface and a desync
risk against the serve-credit table, the single source of truth. Landed:
`release_cooldown.rs` (`whole_record_last_served`), folded at the
`shekyl_archival_verify_unbond_bond_post` FFI.

**Landed representation of `bond_event_log` (F3).** The interval log is
`ArchivalBondValue::bad_intervals` (`shekyl_types.h`): a slash appends an **open**
interval `[E_slash, u64::MAX)` — at most **one** open interval ever exists (same-epoch
slashes coalesce, P2B-9 Pin 5; later epochs are `good_through`-blocked) — `Rebond`
closes it (`end_exclusive = E_rebond + 1`: the partial rebond epoch is forfeited in
both directions, P2B-9 Pin 3, amending the earlier `E_rebond` pin), and a clean
`Unbond` appends the **zero-length** clean interval-close
`[E_unbond, E_unbond)` — `good_through` skips it at every epoch (it can falsify
nothing), so it is purely an event marker that records the exit settlement epoch
for the later `W`-lapse / `p_slot`-burn step. `good_standing` stays a derived
view of this log, never a stored flag.

**`bond_spend_pk` — dedicated bond-debit authorizer (GF-1, gate-6 §9.6).** A `HybridPublicKey`
(`scheme_id = 1`, Ed25519 + ML-DSA-65), **domain-separated from `P_pubkey`** by its own HKDF
labels (gate-6 §9.3 `shekyl-archival-p-bond-spend-{ed25519,ml-dsa-65}-v1`). It is committed
**once, at `JoinMarket`** (bound into the post sig-preimage, §3.4.1) and is **immutable for the
record's life**; it authorizes every later `bond_debit` (`Unbond`, `HoldingsUpdate` drop, §3.5
step 5). This keeps `P_pubkey` (`= hybrid_sign_pk`) **identity-only** — its compromise reveals
nothing spendable — rather than carving the Round-1 identity-only invariant by letting the
account key authorize value-out. It is **not** a custody-model change: the bond stays a
consensus-tracked balance under §3.2 (no key image, no receipt UTXO), so §3.2's round-1 seal is
untouched; `bond_spend_pk` only names *which* key signs the debit. *Rotation:* the key is fixed
per record; re-keying is a full `Unbond` + re-`JoinMarket` (the same model as `P` rotation,
gate-6 §9.2). Reopen per `21-reversion-clause-discipline.mdc` only if a production need for
in-place bond-spend-key rotation emerges (it would be a new consensus op, not a wallet choice).

**`Market` predicate:** §2.2 (per-epoch; includes `E ≥ E_join + 1` and `good_through(E)`).

Foundation `CompleteTree` exclusion from `market_R` unchanged (E-2).

### 4.2 Slash — consensus mutation (forward-only)

Slash is **not** a user transaction and has **no** balance equation. It is a
**consensus-internal transfer** between tracked counters (§4.5), same class as coinbase
emission being rule-driven rather than balance-proven.

**Trigger:** gate-2 `challenge_failed(P,s,E)` at `H > H_deadline` without
`serve_credit_bit` ([`ARCHIVAL_RETENTION_GATE2.md`](../completed/ARCHIVAL_RETENTION_GATE2.md) §6); gate-4
applies `slash(P, s)`.

**Atomic write set (entire slash on block connect):**

1. `bonded_total_atomic -= FLOOR` (or **whole balance** for `CompleteTree` — FOUNDATION §3.2)
2. `holdings` loses shard *s* (or full unbond for foundation)
3. Re-establish `bonded_total_atomic == bond_floor(holdings)` — **`==` pin prevents
   partial-slash theater**; last-shard slash → `0` → out of Market until re-bond
4. `total_bonded_atomic -= slashed_amount`; `burned_total += slashed_amount` (§4.5)
5. Append slash interval to `bond_event_log` (F3)

**Forward-only (invariant 2):** slash at `E_slash` does **not** rewrite finalized
`R_market(s,E)` / `Σwork(E)` for `E < E_slash`. Pre-slash honestly-earned epochs stay
claimable (E-3). `R_market` reduction is automatic at the **next** epoch-close when `P` no
longer satisfies the Market predicate — slash never mutates the finalized past.

### 4.3 Clean unbond vs slash unbond (G4-1)

| Path | Trigger | Collateral | `good_through` for served epochs |
|------|---------|------------|----------------------------------|
| **Slash** | Failed challenge | Forfeited → burn accounting (§4.5) | Pre-slash honest epochs preserved (E-3) |
| **Unbond** | Operator exit + cooldown | Returned to `P` | Clean interval-close in event log |

Without **Unbond**, a never-slashed exiting `P` cannot recover collateral — no rational
bonding. Corpus gap noted: [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) iteration-3
item 6 ("graceful-exit return") — now spec'd here.

**FSM ([`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)):** `Exited` gains **Unbond**
action; sub-condition **collateral in cooldown** until release cooldown elapses. Full
retirement = **bond released** ∧ backlog exhausted or lapsed (`W`). `p_slot` burn follows.

### 4.4 HoldingsUpdate — partial unbond principle (G4-6)

**Wire:** **V3.0** (`HoldingsUpdate` vin). Promoted from deferred-V3.1 (decided
2026-06-15): the bond lifecycle is consensus-state-machine balance, so adding mid-life
shard adjustment post-genesis would be a hard fork; and without it the only way to add or
shed a single shard is `Unbond` + re-`JoinMarket` — tearing down a working multi-shard
operation (all collateral into release cooldown, all serving interrupted, all serve-credit
continuity reset) to swap one slot. The full lifecycle
(`JoinMarket / Rebond / HoldingsUpdate / Unbond`) ships at genesis. Sim reconciliation of
the resulting age-stratified mobility friction is a pre-seal dependency
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*steady-state frame* item 6).

**Principle (grace-tail, ratified 2026-07-15):** dropping shard *s* from `ShardSetCompact`
reduces `bond_floor(holdings)` by `ARCHIVAL_BOND_FLOOR`. The **release cooldown is a verify
precondition on the drop**, not a post-drop state (the same model as `Unbond`): the drop of
*s* cannot be posted until *s*'s release cooldown has elapsed (`release_cooldown_elapsed` on
*s*'s per-shard last-served epoch) **and** the slash scheduler has settled through that
anchor (`slashes_settled_through`). At connect the shard leaves `holdings`, `bonded_total −=
FLOOR`, and the `FLOOR` returns immediately via the `bond_debit` source term (§3.2) — no
`collateral-in-cooldown` sub-state, no `bond_event_log` drop interval, no clean-close marker
(`P` stays `Bonded` with ≥1 shard). The drop is additionally gated by the **retention-horizon**
(`bond_duration(ShardAgeAtAdd(s))`, §4.4 slice-A freeze / P2B-7 Pin 3): a shard younger than
its horizon is ineligible for voluntary drop at all. (Supersedes the earlier
"cannot withdraw immediately" drop-then-cool wording — the same fossil as the `Unbond` "stays
slashable" language; see `PHASE_2B_FSM_RETOOL.md` P2B-7 Pin 2/3.)

**Retention-horizon freeze (LANDED — slice A, 2026-07-14).** The `bond_duration(age)`
drop-eligibility gate (§3.4 asymmetry table; P2B-7 Pin 3 / P2B-8 Q3) is
`current_epoch − add_epoch(s) ≥ bond_duration(ShardAgeAtAdd(s))`, both operands
powered by the one v3.0 per-shard add-epoch record field (landed in slice B). The
formula is genesis-frozen in `shekyl-archival-retention::bond_duration`:
`bond_duration(age) = BASE·(1 + SCALE·age)` (integer-canonical, round-half-up, floored
at 1; `BOND_DURATION_{BASE_EPOCHS,AGE_SCALE}` = 4/4 provisional, config-generated), with
`age = shard_age_milli` **evaluated at the shard's add-epoch settlement close**
`H_close(add_epoch)`. **Age-realization invariant (STATED, genesis-frozen):** the sim
feeds one age variable into both the scarcity/reward curve and the retention lock, and
consensus already realizes that age as `shard_age_milli` in the reward path
(`scarcity_milli`), so retention **consumes the same realization** — `bond_duration` and
`scarcity` read one age, `shard_age_milli @ H_close(add)`; forking a separate age for
retention would split a normalization the sim never split. The freeze rests on this
stated invariant, not on the implementation (full statement + the sim source trace:
`ARCHIVAL_TIMING_CONSTANTS.md` §1). The `ShardAgeAtAdd` newtype makes age-at-drop and
raw-block-height evaluation unrepresentable at the type; the integer formula is proven
bit-identical to the sim's f64 model over the full age sweep (integer authoritative). The
drop verify/connect that *consumes* this gate lands in slice C.

**Safety for deferral:** `work_P(E)` is derived from per-`(P,s,E)` **retention bits**, not
the mutable holdings descriptor. HoldingsUpdate cannot corrupt historical work; descriptor =
current membership, bits = per-epoch ground truth.

### 4.5 Supply conservation law (G4-3 — closed)

Monero-lineage conservation with one new term (PHASE_2B §7 G11 cross-ref):

```text
already_generated_coins  ==  circulating + bonded + burned
```

| Event | `already_generated` | `circulating` | `bonded` | `burned` |
|-------|----------------------|---------------|----------|----------|
| Coinbase / emission mint | +R | +R | — | — |
| Post / fund (`bond_credit`) | — | −credit | +credit | — |
| Release (`bond_debit`) | — | +debit | −debit | — |
| Slash | — | — | −s | +s |
| Fee burn (`actually_destroyed`) | — | −b | — | +b |

`circulating` is the hidden-amount UTXO total (not directly summable on chain). RHS scalars
define **expected** circulating supply; per-tx RCT balance soundness keeps it honest — same
§9 / G11 inflation discipline as emission mint.

**Global audit scalar:**

```text
total_bonded_atomic  ==  Σ_P bonded_total_atomic     // full-node cross-check
```

LMDB placement: sibling to `already_generated_coins` and cumulative burn total (single-valued;
no DUPSORT). Slash soundness is audited by the conservation law, not a balance proof.

**Economic note:** at equilibrium, `FLOOR × Σ covered-(P,s)` is **deliberately immobilized
circulating supply** (locked fraction), not destroyed — distinct from burn. Worth one line in
gate-1 / sim economics when the numeric cluster lands (§8.2).

Slashed bond routes through the **existing burn counter** — one auditable burned total, not a
new sink. `get_block_reward` accumulation is undisturbed (bonds never mint).

---

## 5. Reorg (`pop_block`)

**Per-block pop is all-types-atomic** (single LMDB txn): revert every state type the block
touched — bond credit/debit + `bonded_total_atomic` + `total_bonded_atomic`, record
create/update/delete, same-block retention bits / counts, FCMP++ outputs, interval-log pop.

**Cross-block cascade:** JoinMarket gates gate-2 bit-writing (§1.4). Reverting join at `H`
un-authorizes retention / `R_market` / `Σwork` updates `P` contributed **after** `H`. That
cascade is handled by **ordered multi-block pop** (tip → `H`, archival state §6): later
blocks' bits revert in their own pops **before** the join block is reached — no orphan bits
when the record is deleted at `H`.

On block disconnect at height `H`:

1. **JoinMarket** in block: delete `ArchivalBondRecord` iff `join_market_height == H`;
   revert `bond_credit`, `total_bonded_atomic`, same-block gate-2 writes for `P`.
2. **Rebond / Unbond / HoldingsUpdate** in block: revert record + balance terms in reverse
   connect order.
3. Emission leg §8: paying-emission dedup + mint undo (separate vin path).

Wallet ([`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-5): `Bonded` →
`AdmissionPending` when (1) fires; else re-fetch record and refresh caches.

---

## 6. Gate-6 coupling (join-Market is a standing timing event)

join-Market cannot be hidden inside a mint (§1.2). Gate-6 must **defang** the event:

| Surface | Obligation |
|---------|------------|
| §2.3 Timing | Decorrelate principal funding from join-Market (delay, jitter) |
| §2.5 Bond-funding | Prefer fund-from-earnings ramp; avoid lump principal→`P`→join beacon |
| §2.4 Output | Unrelated to join; drain decorrelation remains separate |

Pin joint disposition in gate-6 Round 2+ with this doc's join event as the named anchor.

---

## 7. Rejected / deferred

| Item | Disposition |
|------|-------------|
| Bond record at first paying mint only | Rejected — violates §1.2 lag |
| Pre-join retention bits | Rejected — §1.4 |
| Zero-mint emission as join vehicle | Rejected — §3.1 (a) |
| `Bonded-not-emitted` FSM state | Rejected — empty dedup in `Bonded` |
| UTXO-shaped bond (attest / spend-lock) | Rejected — §3.2 G4-2 |
| `BondAttestation` proof object | Rejected — balance-equation terms suffice |
| `bonded_total > bond_floor` (over-bond) | Rejected — §3.2 `==` pin |
| Claim/count at `E_join` (partial epoch) | Rejected — §2.2; use `E_join + 1` |
| Bond recovery via drain only | Rejected — §4.3 G4-1 |
| Slash wire bytes | Deferred — gate-4 round 1+ |
| `total_bonded_atomic` LMDB placement | Deferred — with archival state schema (§4.5) |
| `HoldingsUpdate` wire | **V3.0** — promoted from deferred-V3.1 (2026-06-15); principle §4.4 |

---

## 8. Open pins (gate-4 round 1)

**Closed at round 1:** custody model (§3.2); `bond_credit`/`bond_debit` wire; conservation
law (§4.5); `== bond_floor`; UTXO framings rejected.

**Remaining (implementation):**

- [x] **Numeric cluster** — [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)
      (2026-06-07 pin).
- [x] **Slash trigger interface** — [`ARCHIVAL_RETENTION_GATE2.md`](../completed/ARCHIVAL_RETENTION_GATE2.md)
      §6 `challenge_failed` → §4.2 `slash(P,s)`; consensus hook landed (`process_archival_slash_at_height`).
- [x] C++ / Rust `txin_archival_bond_post` vin registration (`tag 0x05`, `bond_wire`, §3.4.1).
- [x] `bond_credit`/`bond_debit` in RCT balance verifier (`verRctSemanticsBondPost`; NIC path).
- [x] JoinMarket connect: `put_archival_bond_record` + `total_bonded_atomic`.
- [ ] Rebond / Unbond / HoldingsUpdate connect paths — **V3.0 scope** (promoted 2026-06-15;
      FSM actions in [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)).
- [ ] **Dedicated bond-spend key (GF-1, gate-6 §9.6)** — commit `bond_spend_pk` into the record
      on `JoinMarket` connect (§4.1); verify `bond_debit` paths' bond-vin `pqc_auths` against the
      committed `bond_spend_pk` and **reject** the account `P_pubkey` as a debit authorizer (§3.5
      step 5); add the `bond_spend_pk` field + `JoinMarket`-conditional bytes to `bond_wire`
      (§3.4.1). Pairs with the gate-6 `shekyl-archival-p-bond-spend-*` HKDF labels + KAT.
- [x] **KAT phase-1 (bonded-aggregation sub-invariant only):** `gate4_lifecycle_kat_v1.json` +
      `gate4_lifecycle_kat.rs` — join wire, serve at `E_first`, `verify_conservation_snapshot`
      on `total_bonded == Σ_P bonded_total`. **Three qualifiers on closure:**
      (1) bonded-aggregation identity only, not the full supply law;
      (2) KAT-covered in Rust tests, not consensus-enforced per connect;
      (3) paying-emit leg and full `already_generated == circulating + bonded + burned`
      deferred to emission phase-0.
- [ ] KAT phase-2: paying-emit vin + full supply-law cross-check (blocked on emission leg).

**Rust-first disposition (gate-4 §8 slice):** new bond-post semantic rules live in
`shekyl-archival-retention`; C++ `blockchain.cpp` retains hybrid-pubkey bounds,
`P_canonical_id` recompute (pinned stay-C++), LMDB `record_exists`, and thin FFI
delegation. `ArchivalBondValue` LMDB encoding is v3-only at connect; pre-v3 bond
blobs are rejected at decode (pre-genesis posture: reset data-dir).

### 8.1 `bond_floor(holdings)` (G4-7)

```text
bond_floor(ShardSetCompact(set)) = ARCHIVAL_BOND_FLOOR × |set|
bond_floor(CompleteTree)         = ARCHIVAL_BOND_FLOOR × 1   // nominal; FOUNDATION §3.1
```

Foundation `CompleteTree` is **excluded from `Market`** but posts **one** floor bond per
`P`, not `FLOOR × all-shards`. Otherwise genesis foundation slots would owe
`FLOOR × |all shards|`.

### 8.2 Numeric cluster (pinned 2026-06-07)

**Authoritative enumeration:** [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)
(cluster table, §2 couplings, pin procedure). Gate-4 owns **release cooldown semantics**
(§3.4–§4.3); numeric values land in the joint cluster pass, not here in isolation.

**Summary (do not re-pin locally):**

| Constant | Role |
|----------|------|
| `SETTLEMENT_EPOCH_BLOCKS` | `E_join`, epoch-close cadence |
| `MAX_CLAIM_AGE_W` (`W`) | E-3 backlog forfeiture |
| `RELEASE_COOLDOWN_EPOCHS` | Anti front-run before `Unbond` (floored by L16 + gate-2) |
| `ARCHIVAL_REORG_DEPTH_BLOCKS` | Wallet + consensus `pop_block` depth |
| `RETENTION_HORIZON_BLOCKS` | Archival derived-state retention floor |

**Asymmetry (load-bearing):** `RELEASE_COOLDOWN_EPOCHS < W`. Collateral return and reward
backlog are independent value flows (§3.5).

---

## 9. Related documents

| Doc | Relationship |
|-----|----------------|
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Mint consumer; §6.4+ amended for join |
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | §2.4 tx legs; FSM retool target |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | `Market`, `E_join`, no pre-join bits |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | Timing + bond-funding around join |
| [`FOUNDATION_GENESIS_IDENTITY_SET.md`](FOUNDATION_GENESIS_IDENTITY_SET.md) | Re-bond after slash |

---

## Revision history

- **2026-06-07 (R1 base):** Consensus-balance custody; `bond_credit`/`bond_debit`; conservation
  law; `== bond_floor`; slash forward-only; reorg all-types-atomic; §8.2 numeric cluster.
- **2026-06-07 (G4):** G4-1 `Unbond` + cooldown; G4-2 custody model; G4-3 supply coupling;
  G4-4 `E_join+1`; G4-5 unified Market predicate; G4-6 HoldingsUpdate principle; G4-7
  `bond_floor` CompleteTree exception.
- **2026-06-07:** Round 0 — join-Market seam; `txin_archival_bond_post` sketch; reorg;
  emission/FSM cross-amendments.
- **2026-06-15:** `HoldingsUpdate` promoted deferred-V3.1 → **V3.0** (§3.2, §3.4 enum, §4.4,
  §6 table, §8 checklist). Full bond lifecycle ships at genesis; FSM actions tracked in
  `PHASE_2B_FSM_RETOOL.md`; age-stratified mobility-friction sim reconciliation is a pre-seal
  dependency.
- **2026-06-16 (GF-1-carve resolved):** Dedicated **`bond_spend_pk`** authorizes `bond_debit`,
  named explicitly at source so the carve does not happen by inertia. Added `bond_spend_pk` to
  `ArchivalBondRecord` (§4.1, committed at `JoinMarket`, immutable) and `ArchivalBondPostVin`
  (§3.4, `JoinMarket`-only wire field, §3.4.1) bound into the post sig-preimage; re-worded §3.5
  step 5 to split bond-vin auth — `bond_spend_pk` on debit (`Unbond`/`HoldingsUpdate` drop),
  `P_pubkey` on credit — so the account identity key never authorizes a value-out (Round-1
  identity-only invariant preserved). Custody model (§3.2) **unchanged** — still consensus-balance,
  no key image / receipt UTXO. Gate-6 §9.3 adds the `shekyl-archival-p-bond-spend-{ed25519,ml-dsa-65}-v1`
  HKDF labels + KAT obligation. Closes `ARCHIVAL_FIREWALL_GATE6.md` §10.11 GF-1-carve.
