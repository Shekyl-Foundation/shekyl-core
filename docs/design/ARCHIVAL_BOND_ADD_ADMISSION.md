# Bond admission accepts only valid, closed, final shards — the ghost-shard guard

**Status:** **RULED 2026-09-19** (maintainer); **BUILT 2026-10-07 as `CEN-J15`**
(#983, `shekyl-chain-rules` `rules/tx_bond.rs`, `census.rs:509` `J15 implemented`).
§4 answers the three design questions. The record is
[`CHAIN_RULES_SLICE_8.md`](../completed/CHAIN_RULES_SLICE_8.md) §3.4. The ruling
was grounded at `dev` = `6c41bf820` (the #790 merge) and re-based onto
`fbc92287a` (the #795–#798 `PDM` sweep and #786 S-TX).

**Provenance.** This is `WSS-22`, the one remainder of the wallet-side store
round ([`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md) §6.5.5), delivered to the
lane that owns the predicate. The finding is the wallet lane's; the rule is
steering's; the implementation is the daemon lane's.

**Identifier family:** none minted. One ruling and three questions, answered by
an existing lane (**E6 slice 8**, `CEN-J15`; posed to **E4 / S-ARCH**), so this
document registers no series of its own
([`23-disposition-visibility`](../../.cursor/rules/23-disposition-visibility.mdc):
zero code symbols, and no family where the owning lane already has one).

---

## 1. The ruling

> **Bond admission accepts only valid, closed, final shards.**

Two legs, and they do different work:

| Leg | What it rules out | What it rests on |
| --- | --- | --- |
| **"exists"** | a `shard_id` naming no shard — past the end of the partition, or in a partition that does not reach that far yet | **Hygiene.** A bond may not name a thing that is not a thing |
| **"closed and final"** | a `shard_id` whose boundary has not closed (`b_{k+1}` does not exist yet), or whose contents a reorg can still replace | **Determinism — the load-bearing leg.** Membership of an unclosed shard is not yet a fact, and membership of a shard within `D_max` of the tip is not yet a *stable* fact |

The second leg is the one that carries the rule, and it is **an extension, not
an invention**: `PDM-Q6` item 3 already rules the **open frontier shard
non-bondable** (`ARCHIVAL_PRUNED_DAEMON_MODE.md:458-459`). This ruling extends
that reasoning to **the reorg window**, adds the **existence** leg, and states
all of it as **one admission predicate** rather than facts a reader has to
join. §3 is that sizing, as of the ruling. §4 is what was built.

### 1.1 What the rule is *not* justified by

**Not exploit prevention.** There is no exploit here, and the record says so
plainly so that nobody later re-inflates a threat in order to defend the check.
The mechanism digests a ghost unaided (§2). A guard defended by a threat that
does not exist is a guard that falls the moment someone checks the threat.

**It is defense in depth in the exact sense** — a layer *in front of a
mechanism that already works* — and its justification is
**unrepresentability and network economy**:

- **Unrepresentability** ([`05-system-thinking`](../../.cursor/rules/05-system-thinking.mdc)):
  a state that should never exist should not be writable. A bond naming a
  ghost shard is such a state.
- **Network economy:** without the guard the network spends **draws, Tor
  circuits, witness work and slash machinery** destroying a state that should
  never have been admitted. Every one of those costs lands on *other*
  operators — the witness that draws the ghost, the daemon whose circuit is
  spent — not on the `P` that posted it.

**Why this is worth recording as reasoning rather than a conclusion.** The
guard **survived having its scariest justification dismantled.** A rule still
worth its cost after the exploit story dies is a rule standing on **structure**
— which is the strongest place for a consensus rule to stand, and the reason
this document argues it that way.

---

## 2. What happens to a ghost today — the behavioural record

Verified at `6c41bf820`. This is the lifecycle the guard makes unnecessary, and
it is recorded because **it is the evidence that the rule is not load-bearing
for safety**:

```text
bond names ghost shard k
        │
        ▼  draws are bond-derived — the drawable set comes from holdings,
        │  so the ghost is drawn like any other shard
   witness draws (P, k)
        │
        ▼  P has no bytes for k and answers the SINGLE SHARED 404
        │  (provider.rs:239 — "only the local counters tell them apart";
        │  :38 — a distinct failure would itself be a signal)
   the challenge expires with no pass — and that IS the miss
        │  "A miss is never asserted. It is the expiry of a derived
        │   challenge with no pass recorded within W2. No miss record
        │   exists on the wire" (ARCHIVAL_CHALLENGE_MECHANISM.md:184-187)
   no serve-credit bit is set
        │
        ▼  2-of-3 within an epoch, m-of-n across epochs, recomputed
        │  from the serve_credit_bit ledger + bond record every time —
        │  "Nothing is persisted" (db_lmdb.cpp:5744-5751)
   observed across epochs
        │
        ▼
   the ordinary m-of-n slash
```

**Three properties of that path worth naming**, because each is why the ghost
needs no special handling:

1. **The 404 is the ordinary one.** A ghost shard is indistinguishable on the
   wire from any other miss — no new response, no new state, no new branch.
2. **No leg treats the ghost specially, and none writes any *ghost-specific*
   state.** Every step is the path a withholding `P` already takes, so a ghost
   costs the mechanism no new code and **no new state along the way**: a miss
   is never asserted, only the **absence** of a pass within `W₂`, and the
   m-of-n window is **recomputed** from the `serve_credit_bit` ledger and the
   bond record on every evaluation rather than stored. There is no miss record
   for a ghost to create. **The terminal slash does write** — the bond,
   `total_bonded`, `total_burned`, the slash-applied bit and the slash log
   (`db_lmdb.cpp:5964-5985`) — but those are the **ordinary** slash's writes,
   identical to any withholding `P`'s, which is the point: the ghost adds
   nothing to them.
3. **The cost falls on the poster.** The slash lands on the `P` that named the
   ghost. What the guard saves is not `P` from itself but the **network** from
   spending real work to reach that conclusion.

---

## 3. What predecessor exists, and what does not — sizing the work

**This is the correction the wallet round returned, and it changes the shape of
the daemon lane's task.** It is easy to read the missing guard as a re-key —
the leaf era had `frozen_segment_count`, so surely the byte era needs its
successor. **It is not a re-key — but the precise statement matters to whoever
sizes the work, so state it precisely rather than as a flat "no predecessor":**

| Half | Predecessor in **design** | Predecessor in **code** |
| --- | --- | --- |
| **"closed and final"** | **Partly yes.** `PDM-Q6` item 3 already rules the **open frontier shard** (no `b_{k+1}` yet) **not bondable** — *"a clean `HoldingsUpdate` admission rule the per-tx model did not give"* (`ARCHIVAL_PRUNED_DAEMON_MODE.md:458-459`; the quoted kind is REJECTED 2026-09-20 and the source struck it 2026-09-22 — the rule now admits at `JoinMarket`, the only bonding event). Silent on the reorg window, which this ruling adds. **Unbuilt at the ruling** | **Built 2026-10-07** as `CEN-J15` |
| **"exists"** | **No** | **Built 2026-10-07** — a shard past the frontier fails `closed_and_final` (`rust/shekyl-chain-rules/src/archival/close.rs:302`) |

So the task, sized on 2026-09-19, was **a new rule plus an unimplemented old
one**, not a translation and not a greenfield. The evidence for that code
column, at the pin:

- `ShardSet::new` — *"the one fallible constructor — every decoder / FFI
  marshal / builder routes through it"*
  (`rust/shekyl-archival-retention/src/bond_wire.rs:210-227`) — enforces
  **`MAX_HOLDINGS_SHARDS` and duplicate-freeness, and nothing else.** No bound
  against chain state.
- Nothing in `bond_post.rs` / `bond_connect.rs` / `bond_floor.rs` bounds a
  `shard_id` against chain state either.
- **And the inherited claim that one does is unsupported at its call sites.**
  [`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) (2026-09-17) says
  of `frozen_segment_count` that *"bond admission reads it to decide which
  `shard_id`s are admissible"*. Its three consumers are the **D2 escalation
  operand** (`src/cryptonote_core/blockchain.cpp:1502`, and its own comment
  names it as such), the **coverage RPC**
  (`src/rpc/archival_shard_coverage.cpp:34`), and the **freeze / pop-revert**
  path (`src/blockchain_db/lmdb/db_lmdb.cpp:7997`). **None is bond admission.**

The daemon lane was **building**, not porting. **It is built** (§4). A reader
who trusts the inherited `frozen_segment_count` claim still finds no bond
admission among its consumers; the Rust rule is `CEN-J15`, not a port of that
symbol. The C++ gather admits a strict superset of what `CEN-J15` admits
(open, unpriced shards clear there) and deletes at the cutover
(`DAEMON_REDB_STORE.md`, the `DEL-008` permissive row on
`check_archival_bond_post_input`). **The design intent reused is `PDM-Q6`
item 3's non-bondable frontier shard**, a paragraph honoured rather than
code ported.

---

## 4. The design questions — ANSWERED 2026-10-07 (CEN-J15)

The rule was posed to E4 / S-ARCH. E6 slice 8 answered it as `CEN-J15`
(#983). The record is
[`CHAIN_RULES_SLICE_8.md`](../completed/CHAIN_RULES_SLICE_8.md) §3.4. The code
is `rules/tx_bond.rs` and `archival/close.rs`.

| # | Question | Answer |
| --- | --- | --- |
| **1** | **Where does the predicate live?** | In `shekyl-chain-rules`. `closed_and_final` is `rust/shekyl-chain-rules/src/archival/close.rs:296`. `J15` calls it from `rust/shekyl-chain-rules/src/rules/tx_bond.rs:501`. The viability leg is the retention crate's `check_admission` (`rust/shekyl-archival-retention/src/admission.rs:420`). Slice C consumes this predicate; it does not own a second site |
| **2** | **At what height is it evaluated?** | At the admitting block's parent. `parent` is `Tip::connecting_height(view.tip()) − 1` (`rust/shekyl-chain-rules/src/rules/tx_bond.rs:486`). `validate` judges over that parent `ChainView`, so a read taken after the connecting block advances the chain has no expression here. A compact set at genesis has no parent and is refused |
| **3** | **Does `ShardSet` gain chain context, or does a separate check own this?** | A separate check. `ShardSet::new` (`rust/shekyl-types/src/archival/mod.rs:414`) stays the pure constructor: cardinality and duplicates, no chain. The chain check is `closed_and_final(view, shard, parent, reorg_cap)` |

### 4.1 What the predicate reads

`J15` reads these and mints none of them:

- **Closed and final** — `closed_and_final(view, shard, parent, rule_set.reorg_cap())`.
  The cap is `RuleSet::reorg_cap()`, the reorg-cap job. A shard at or past the
  frontier fails the closed leg (`rust/shekyl-chain-rules/src/archival/close.rs:302`);
  that failure is the existence leg.
- **The price** — `view.r_market(shard, last_settled_slash_epoch)`. Absent
  watermark or absent row refuses (slice 8 Q4; `rust/shekyl-chain-rules/src/rules/tx_bond.rs:504`).
- **Viability** — `check_admission` over that price and the age of the close
  `closed_and_final` just placed. A complete tree gathers nothing and is
  admitted (`rust/shekyl-chain-rules/src/rules/tx_bond.rs:483`).

*Was:* a gate that the predicate could not be implemented before the A4
length rows (S-CHAIN-W) and S-PRUNE's `b_*` forward pass, with
`close_height(k)` searched over `cumulative_tx_count`. Dissolved.
`PDM-Q6` item 5 withdraws A4, and `SHT-Q2` keys the frontier by
`shard_of(cumulative_archival_len)` (`CHAIN_RULES_SLICE_8.md` §3.4). The
wallet fill still wants `b_*` and `close_height(k)` as readable daemon
facts (§5). Admission reads the fold, the price, and the viability check
above.

**Rule 94.** This document mints no family. The answer's family is `CEN-J15`
(#983), stamped on this document's row in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §7. The questions point
at the lane, and the lane's row points back.

---

## 5. What this closes elsewhere

- **`WSS-22`** — the wallet round's finding, delivered.
- **`WSS-Q6` / `WSS-Q10`'s daemon-lane halves.** The admission rule those
  halves were waiting on is `CEN-J15` (§4). What remains is `b_*` and
  `close_height(k)` as readable daemon facts for the wallet fill
  ([`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md)). The A4 / S-PRUNE gate
  those halves were also waiting on is dissolved (§4.1).
- **`CompleteTree`'s *owed* set** is *"every closed, final shard"*
  (`WALLET_SIDE_STORE.md` `WSS-Q10`), the same predicate the admission guard
  applies — one definition, two consumers.

---

## 6. Decision log

| Date | Decision |
| --- | --- |
| 2026-09-19 | **RULED (maintainer): bond admission accepts only valid, closed, final shards.** Two legs — *"exists"* as hygiene, *"closed and final"* as the determinism load-bearer, extending `PDM-Q6` item 3's non-bondable frontier shard to the reorg window. **Justified on unrepresentability and network economy, explicitly *not* exploit prevention:** the mechanism digests a ghost unaided — bond-derived draws, the single shared 404 (`provider.rs:239`), recorded misses, no credit bit, m-of-n across epochs, the ordinary slash — so the guard is defense in depth in the exact sense, a layer in front of a mechanism that already works. **No *ghost-specific* state is written along the way** — the terminal slash writes exactly what any withholding `P`'s slash writes (`db_lmdb.cpp:5964-5985`), which is the point. It spares the **network** the draws, circuits, witness work and slash machinery, not `P` from itself. **The reasoning is recorded, not just the conclusion, because the guard survived having its scariest justification dismantled** — a rule still worth its cost after the exploit story dies stands on structure, and nobody should later feel the need to re-inflate the threat to defend it. **Correction carried from the wallet lane, stated precisely:** the task is **a new rule plus an unimplemented old one** — `PDM-Q6` item 3 already rules the open frontier shard non-bondable in **design** (`:458-459`, unbuilt, silent on the reorg window), while the **existence** half has no predecessor at all and **neither half has one in code** — `ShardSet::new` enforces only cardinality and duplicate-freeness (`bond_wire.rs:210-227`), and `frozen_segment_count`'s three consumers (D2 escalation operand, coverage RPC, freeze / pop-revert) are **none of them** bond admission, contrary to the 2026-09-17 decision-log sentence. Three design questions left to **E4 / S-ARCH**: the predicate's site, its evaluation height (with `blockchain.cpp:1478-1492`'s read-point hazard applying), and whether `ShardSet` gains chain context or a separate check owns it — the last trading one fallible constructor against a pure one. |
| 2026-10-10 | **The three §4 questions are answered, and the predicate is built.** `CEN-J15` (#983, E6 slice 8). Site: `closed_and_final` in `archival/close.rs`, called from `rules/tx_bond.rs`, with `check_admission` for viability. Height: the admitting block's parent (`connecting_height − 1`). `ShardSet::new` stays pure; the chain check is the rule step. The A4 / S-PRUNE gate in §4.1 is dissolved (`CHAIN_RULES_SLICE_8.md` §3.4). The 2026-09-19 row's "left to E4 / S-ARCH" and "neither half has one in code" are that day's sizing. |
