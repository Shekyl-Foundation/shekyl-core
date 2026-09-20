# Bond admission accepts only valid, closed, final shards — the ghost-shard guard

**Status:** **RULED 2026-09-19** (maintainer). The rule is settled; three
**design** questions are open and belong to the **daemon lane** (§4). Grounded
at `dev` = `6c41bf820` (the #790 merge) and **re-based onto `fbc92287a`**
(the #795–#798 `PDM` sweep and #786 S-TX); every code anchor below re-verified
at that tree. Re-pin before implementing.

**Provenance.** This is `WSS-22`, the one remainder of the wallet-side store
round ([`WALLET_SIDE_STORE.md`](WALLET_SIDE_STORE.md) §6.5.5), delivered to the
lane that owns the predicate. The finding is the wallet lane's; the rule is
steering's; the implementation is the daemon lane's.

**Identifier family:** none minted. This document carries one ruling and three
questions owed to an existing lane (**E4 / S-ARCH**), so it registers no series
of its own ([`23-disposition-visibility`](../../.cursor/rules/23-disposition-visibility.mdc):
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
join. §3 sizes what that leaves to build.

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
   recorded miss
        │
        ▼  a miss yields no serve-credit bit
   no credit bit
        │
        ▼  2-of-3 within an epoch, m-of-n across epochs
        │  (ARCHIVAL_CHALLENGE_MECHANISM.md §3)
   observed across epochs
        │
        ▼
   the ordinary m-of-n slash
```

**Three properties of that path worth naming**, because each is why the ghost
needs no special handling:

1. **The 404 is the ordinary one.** A ghost shard is indistinguishable on the
   wire from any other miss — no new response, no new state, no new branch.
2. **No leg treats the ghost specially.** Every step is the path a withholding
   `P` already takes, so a ghost costs the mechanism no new code.
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
| **"closed and final"** | **Partly yes.** `PDM-Q6` item 3 already rules the **open frontier shard** (no `b_{k+1}` yet) **not bondable** — *"a clean `HoldingsUpdate` admission rule the per-tx model did not give"* (`ARCHIVAL_PRUNED_DAEMON_MODE.md:458-459`). **Unbuilt**, and silent on the reorg window, which this ruling adds | **No** |
| **"exists"** | **No** | **No** |

So the task is **a new rule plus an unimplemented old one**, not a translation
and not a greenfield. The evidence for the code column:

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

So the daemon lane is **building**, not porting — and a reader who trusts the
inherited claim will look for a predecessor, find the C++ symbol, and conclude
the work is a translation. **The one thing it *can* reuse is the design
intent of `PDM-Q6` item 3's non-bondable frontier shard**, which is a paragraph
to honour rather than code to port.

---

## 4. The design questions, owed to the daemon lane

The **rule** is ruled. These are **how**, and they are E4 / S-ARCH's:

| # | Question | Why it is open |
| --- | --- | --- |
| **1** | **Where does the predicate live?** | Admission-side in `shekyl-chain-rules`, or in `shekyl-archival-retention` beside the rest of the bond rules. The verifier that lands at E4 / S-ARCH (`PDM-Q6` item 4, row 1) is the natural neighbour, but that is a placement argument, not a ruling |
| **2** | **At what height is it evaluated?** | Admission reads chain state, so the predicate needs a stated evaluation point — and the same hazard `blockchain.cpp:1478-1492` documents for the D2 operand applies: *"a refactor that moves the read past `add_block` … must stop the node here"*. Whatever height is chosen, **the operand must be captured before the connecting block advances the chain**, or the check becomes a tautology that still passes every test |
| **3** | **Does `ShardSet` gain chain context, or does a separate check own this?** | `ShardSet::new` is currently a **pure** constructor — cardinality and duplicates, no I/O, reachable from decoders, FFI marshals and builders alike. Giving it chain context would change that character on **every** one of those paths. A separate admission-side check keeps the constructor pure. **Trade named, not settled:** one fallible constructor is a strong invariant to keep, and a second check is a second thing to remember |

### 4.1 What the predicate needs, and what supplies it

- **`b_*`** — the shard partition, derived by **S-PRUNE's forward pass over the
  A4 length rows, once**; the verifier *reads* it and mints nothing
  (`PDM-Q9` (iii)).
- **`close_height(k)`** — a binary search over `cumulative_tx_count`
  (`PDM-Q6` item 3); no new state.
- **`D_max`** — `archival_reorg_depth_blocks` = 720
  (`config/consensus_constants.json:26`), for the finality leg.
- **The dense `tx_id` space the partition is derived over.**
  [`DRS_E1_STX.md`](DRS_E1_STX.md) — **landed 2026-09-19, PR #786** — makes
  `tx_count()` the dense count authority over `txs_pruned` (T2, `:233`) and
  records that **`tx_id` order is ruled and dense** (SI-9, STX-10 `:494`). That
  density is what makes *"does shard `k` exist"* a determinate question rather
  than a lookup that can silently answer for a hole.

**Gate on the whole predicate:** it cannot be implemented before the **A4
length rows** land (S-CHAIN-W) and **S-PRUNE derives `b_*`** — the same gate
`WALLET_SIDE_STORE.md` §5 rows 1–2 names for the wallet side.

**The obligation that travels with these questions (rule 94):** this document
mints no identifier family, because the answering lane already has one. **When
E4 / S-ARCH answers, its family is stamped into this document's
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §7 row**, so the trail runs
**both** directions — the questions point at the lane, and the lane's answer
points back at the questions. Without that, a handoff with no family is a
handoff with no return address.

---

## 5. What this closes elsewhere

- **`WSS-22`** — the wallet round's finding, delivered.
- **`WSS-Q6` / `WSS-Q10`'s daemon-lane halves** — both were held open on *"how
  `CompleteTree` admission works"* and on `b_*` / `close_height(k)` becoming
  readable daemon facts. The ruling settles the **admission rule**; those halves
  still wait on §4's answers and on the same A4 / S-PRUNE gate.
- **`CompleteTree`'s *owed* set** is *"every closed, final shard"*
  (`WALLET_SIDE_STORE.md` `WSS-Q10`), which is now the **same predicate** the
  admission guard applies — one definition, two consumers, rather than two
  phrasings that can drift apart.

---

## 6. Decision log

| Date | Decision |
| --- | --- |
| 2026-09-19 | **RULED (maintainer): bond admission accepts only valid, closed, final shards.** Two legs — *"exists"* as hygiene, *"closed and final"* as the determinism load-bearer, extending `PDM-Q6` item 3's non-bondable frontier shard to the reorg window. **Justified on unrepresentability and network economy, explicitly *not* exploit prevention:** the mechanism digests a ghost unaided — bond-derived draws, the single shared 404 (`provider.rs:239`), recorded misses, no credit bit, m-of-n across epochs, the ordinary slash — so the guard is defense in depth in the exact sense, a layer in front of a mechanism that already works. It spares the **network** the draws, circuits, witness work and slash machinery, not `P` from itself. **The reasoning is recorded, not just the conclusion, because the guard survived having its scariest justification dismantled** — a rule still worth its cost after the exploit story dies stands on structure, and nobody should later feel the need to re-inflate the threat to defend it. **Correction carried from the wallet lane, stated precisely:** the task is **a new rule plus an unimplemented old one** — `PDM-Q6` item 3 already rules the open frontier shard non-bondable in **design** (`:458-459`, unbuilt, silent on the reorg window), while the **existence** half has no predecessor at all and **neither half has one in code** — `ShardSet::new` enforces only cardinality and duplicate-freeness (`bond_wire.rs:210-227`), and `frozen_segment_count`'s three consumers (D2 escalation operand, coverage RPC, freeze / pop-revert) are **none of them** bond admission, contrary to the 2026-09-17 decision-log sentence. Three design questions left to **E4 / S-ARCH**: the predicate's site, its evaluation height (with `blockchain.cpp:1478-1492`'s read-point hazard applying), and whether `ShardSet` gains chain context or a separate check owns it — the last trading one fallible constructor against a pure one. |
