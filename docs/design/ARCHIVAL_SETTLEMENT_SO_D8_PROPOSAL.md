# `SO-D8` — ruling-round proposal: cross-epoch admission and the settlement writer's production caller

**Status:** OPEN — **PROPOSAL; direction RATIFIED.** *UPDATE 2026-09-23
(`TX_EXTRA_RUST_CUTOVER.md` TXE-Q6′, census `CEN-I20`): the coinbase extra
is now a closed consensus grammar — exactly `[0x01, 0x02(8), 0x06, 0x07]` —
so a coinbase `0x0C` (or `0x0B`) field is a **grammar amendment ruled in the
census and the wire spec §9.6b**, not a tag allocation; the nonce bound this
file budgets at 255 B is 8 B fixed; and the C++ `tx_extra.h` /
`find_tx_extra_field_by_type` it cites are deleted — the one codec is
`shekyl-wire`'s (`shekyl_tx_extra_field` is likewise first-match by index,
but duplicates cannot occur in a grammar-valid coinbase).* Rick ratified shape
**R-B** (post-issuance window, §2) on 2026-09-13. **RULED 2026-09-16:**
Q3, Q8 (incl. P1/P2), Q9, Q10, Q12, Q13, Q15; Q14 closed by Q15;
`SO-D8a`, `SO-D8b`, `SO-D8c` (transcriptions of R-B / PC-D4 / SO-D7);
`SO-D8d` (three local layers; store-invariant Fault, not a verdict;
amended same day against `dev@5fde3b1ce` — §6.3); `SO-D8e` (forward
urn + `W₂` ring, no checkpoints, one set live, digest carve-out — §7.2).
**Still to be ruled:** Q9's set-commitment bytes (§7.6.1, PROPOSED —
one customization + KAT; carrier semantics RULED (B), §7.6.2). **Q4
RESOLVED 2026-09-17** (one production constructor reads the constant;
`assign_epoch` feeds it; explicit λ is `#[cfg(test)]` —
`fix/so-q4-pin-lambda`). Slice C is not
authorized. `ARCHIVAL_SETTLEMENT_WRITER.md` §12's rule-22 hold on the
writer's call site **stands**. No admission code, no consensus code, and
no writer call site were written for this round (Slices A and B of the
2026-09-13 brief were authorized; Slice C — implementation — was not,
and §8 is its plan, not its work).

**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
security and quantum resilience are preconditions; privacy is second, as the
product. The 2026-09-13 opening brief inverted the top two
(*"privacy > security > correctness > performance > features"*) — **SUPERSEDED
here**. A hiding commitment that weakens the binding is refused; the
privacy gain does not enter the arithmetic. Q12 RULED independently
(§7.9): hiding without stopping the pk reveal is theater, so a bare
hash is the only purchasable option. The hierarchy still binds if a
reopener conceals `h` and forbids publishing `pk`.

> **Line-number era.** `blockchain.cpp:NNNN` citations in this document are
> pinned at `dev@37accf6f` (the brief's read); `dev` has since shed ~195 lines
> above the serve-credit arm, so today's numbers are lower. Identifiers
> (`h_close`, `challenge_seal_on_chain`, `ctx.settlement_epoch`,
> `shekyl_archival_verify_serve_credit_vin`) are stable; re-pin at Slice C.

> **F5 (§1.5) → `PL-D1`, CLOSED by `PL-D3` — PR #745
> (`feat/pl-d3-pedersen-leaf-commitment`), ratified by Rick 2026-09-14.** The
> finding this proposal filed as `F5` on 2026-09-13 — every FCMP++ spend
> linkable to its output by the public 4th leaf scalar — was opened by Rick
> as its own round the same day: `PL-` is the family, `F5` the historical
> name (`docs/design/FCMP_SPEND_LINKABILITY.md`, lands with #745). The fix is
> a **hiding Pedersen commitment to the key** in the leaf's 4th scalar, opened
> in-circuit to the point the verifier derives from the revealed key; it is
> **the** fix for the v3 era — the hash-mechanism successor `PL-D4` is ruled to
> **V4** (Rick, 2026-09-14). **Reconciled against #745 on 2026-09-14** per
> its §12 ruling 11 (*"whichever lands second reconciles to one FOLLOWUPS
> line and a cross-reference"*): this proposal's `FOLLOWUPS.md` line is
> withdrawn in favour of the `PL-` round's, and §1.5, §2.2, §8, §9 and Q8 now
> stand on `PL-D3`'s stated premise — *the key appears once, at spend, and is
> published nowhere at creation* — rather than on the defect's persistence.
> **#745 merged 2026-09-14** (`c405fac0a` is SO's own merge the same hour;
> `PL-D3` is on `dev`). Sequencing against `PL-D3` is discharged.
>
> **Q15 RULED 2026-09-16 — Rust-direct; no C++ mirroring.** Rick: *"the SO
> can wait until it can be written directly into Rust — there is no need
> for C++ mirroring."* Substrate is **DRS-D12** (ratified 2026-09-15,
> [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) DRS-D12 / [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md)):
> consensus rules live in **one** crate, `shekyl-chain-rules`, with no
> store handle; an FFI shim minting `ChainValid` from a C++ verdict is
> **rejected**. §8's 2026-09-13 plan (Rust logic behind a C++ marshaling
> shim in `blockchain.cpp`, *"if redb's `apply_block` lands first the FFI
> half is simply never written"*) is **SUPERSEDED** in place.
>
> **Pin (2026-09-16): S-CHAIN-W is landed, not open.** DRS-E1 increment 3
> — the connect/pop write set — landed 2026-09-15 (PR #757 merged
> 2026-09-16): `connect(ChainValid, ConnectFacts, RuleSetId)` / `pop()` on
> the branded batch, SI-1/2/3/4/6/8/9 built, the writer halt
> (`DAEMON_REDB_STORE.md:11`, S-CHAIN-W row **LANDED**). The daemon still
> opens LMDB only; `shekyl-chain-rules` declares its rows with none built
> (B3, H5, L1 `pending` at `census.rs:216/280/360`). DRS is **one increment
> from a validator** (E6 rule bodies), not mid-increment.
>
> **The six admission gates split; it is not one increment gated on
> S-ARCH (priority 7 of 9).** D12: rules arrive surface-bound or as E6
> increments. Three rows are landable as E6 increments whenever E6 takes
> them; a fourth is nearer than S-ARCH:
>
> | Gate | Surface | Home |
> |---|---|---|
> | deadline `h < h_incl ≤ h + W₂` | arithmetic on the candidate plus `h`; **surface-free** | E6 increment |
> | SO-D9 `epoch(h) == E` | **surface-free** | E6 increment |
> | `0x0C` content (Q13 RULED) | coinbase `tx_extra` predicate, no store handle; **surface-free** | E6 increment |
> | witness verification | `h`'s coinbase commitment from `tx_extra`; **surface-bound to the block/tx surface**, which ports well ahead of S-ARCH | E6-or-tx, not E4 |
> | membership against `assignment(h)` | drawable set produced by `DrawableSet::at_epoch_open` (Q3 RULED, chain-rules over `ChainView`; no snapshot table). Gate still **surface-bound to S-ARCH** with the writer — Q3 names the producer, it does not re-home the gate | E4 |
> | dedup `(P,s,E,h)` exact-get | **surface-bound to S-ARCH** | E4 |
>
> Waiting is **stronger than the shim prohibition.** Landing R-B
> pre-cutover writes the gates into `blockchain.cpp`; the port then
> re-derives them as census rows. Re-derivation is where DRS §7.5's
> partition gains a row nobody graded against the original. Worse: R-B
> moves a genesis-frozen wire byte (`h` on the kept side, 117 → ~125,
> rule 42 plus a version bump). Doing that once pre-cutover in C++ and
> once again as a chain-rules row is two bites at a frozen surface for
> one change.
>
> **Corollary:** the pre-cutover daemon keeps the beacon, so
> `ARCHIVAL_SETTLEMENT_WRITER.md` §5.1's interim-writer question stays
> **closed** and is not revisited.
>
> **Q14 prohibition (not a sequencing note):** SO-D9's C++ tautology
> **must not be repaired in `blockchain.cpp`.** Making that check fire is
> a consensus tightening on the live LMDB daemon, for a code path that is
> being replaced — a tightening nobody needs, on the shorter-lived of the
> two implementations. In chain-rules SO-D9 is a positive row with a
> negative fixture; the tautology never ports. Recorded so a later sweep
> does not read the vacuous comparison as a bug and fix it helpfully.
>
> Admission gates land as new `CEN-` rows (ids minted at Slice C, next
> free in their family — not here); the writer call site lands on the
> Rust apply/slash path when **S-ARCH** (DRS-E4) ports the settlement
> table; C++ never learns either. Falsify by `shekyl-chain-rules` being
> the live connect validator (`ChainValid` minted without a C++-verdict
> shim) **and** a production caller of the settlement write in the Rust
> apply/slash path. Until both, Slice C is not authorized. Q14 is
> resolved by this ruling (§10). **Q12 RULED 2026-09-16 (§7.9):** bare
> 32-byte hash, on its own analysis, not as F5 inheritance. *SUPERSEDED:
> "Q12 is sequenced behind F5."*

**Grounded at** `dev@37accf6f` (fresh worktree `~/shekyl/wt-so-settlement`,
branch `feat/so-a-settlement-surface` carrying the three Slice-A commits
`cf09d6f3e`, `dc070a985`, `a6f602d33`). Every `file:line` below was read at
that tree on 2026-09-13; where a line number is quoted from an older document
it is marked as such.

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
No new identifier family is minted: sub-dispositions here are `SO-D8a`…`SO-D8e`,
which parse under the registered `SO-` prefix (rule 94 §1) and are folded back
into `ARCHIVAL_SETTLEMENT_WRITER.md` §12/§13 when ruled. This file then
archives per rule 95.

---

## 0. What this round was opened to rule, quoted

`ARCHIVAL_SETTLEMENT_WRITER.md` §12 (2026-08-24):

> Under derived assignment a challenge issued in the epoch's last `W₂` blocks
> resolves *after* `h_close`, so its response names epoch `E` while landing in
> `E+1`'s blocks. […] What is genuinely open is the arithmetic at the boundary:
> a response naming `E` admitted during `E+1`, and what dedup and the emission
> gather do with it.

The brief's five items: (a) boundary arithmetic, (b) dedup at
`blockchain.cpp:5156`, (c) emission-gather handling of cross-epoch records,
(d) `passes > issued` after relaxing the deadline, (e) the `assign_epoch` FFI
shape.

**§1 finds that `SO-D8`'s premise stands, and that the round has MORE to rule
than §12 listed, not less.** A record naming `E` is fully representable in a
block of `E+1`; exactly one live consensus rule refuses it today (the C++
`h_close` gate), and the "ruled per-challenge deadline" §12 proposed
re-pointing that gate at **does not exist in code**. §2 states the two shapes
the ruling can take and records which was ratified; item (e) is where the
implementation work is under either.

> **CORRECTED 2026-09-13 (Rick's review of the first cut, same day).** The
> first cut of this section claimed the premise was *"unrepresentable on the
> frozen wire and refused by two live gates"* and that items (a)–(d)
> *dissolve*. That rested on reading `ERR_EPOCH_MISMATCH` as a check of the
> record's epoch against the block's. **It is a tautology** — SO-D9 below — and
> once it is removed from the argument the dissolution does not survive. The
> wrong finding is struck here rather than deleted because an agent that read
> the first cut will otherwise build against it; the class is recorded in
> §1.2. The reviewer's walk is the authority for this correction; every line
> anchor was re-read at the tree before the text was changed.

---

## 1. Findings — what actually binds a record, read at the admission path

### F1 — the wire binds a record to the block it rides in, and to a **prover-declared** epoch

| # | Binding | Where | Holds? |
|---|---|---|---|
| 1 | `PC-D3`: `challenge_leaf_index(P, s, E, prev_block_hash, leaf_count)` — the challenged leaf is drawn by the **including block's predecessor**, and the index is inside P's signed preimage together with `R_k`, the leaf bytes and the path | `blockchain.cpp:5307` (`ctx.prev_block_hash`), `serve_credit.rs:182–188`, `wire.rs:379–402` (`signature_preimage`) | **Yes.** A countersignature made against block `h`'s predecessor verifies in no block with a different predecessor. **This is the vin's only block binding** — see F3 for what the first cut put here instead. |
| 2 | Beacon fire height `challenge_fire_height(h_open, h_close, block_hash_at_seal, P, s, E)` from `ctx.block_hash_at_seal` | `blockchain.cpp:5305`, `serve_credit.rs:190–198`, gate at `:208–209` | **Yes**, and it **dies with the beacon** under derived assignment (§3). |
| 3 | Kept header is `p_id ‖ shard_id ‖ settlement_epoch ‖ Ed25519 countersig` — no issuing height, no claimed block | `cryptonote_config.h:424–426` (`1 + 32 + 10 + 10 + 64 = 117`), `shekyl-wire/src/transaction.rs:184,:197` | **Yes.** There is no field in which a record names an issuing `h`. |
| 4 | `settlement_epoch` in that header is **written by the prover** and parsed by C++ at `get_archival_serve_credit_key` | `blockchain.cpp:5124` | **Yes** — and this is the row the first cut missed: **nothing in rows 1–3 ties `E` to the including block's epoch.** |
| 5 | The live rules relating `E` to the block's height are **two bounds on `E`**: `if (current_height > h_close(E)) reject "past credit deadline"` (upper bound on height → lower bound on `E`), and `challenge_seal_on_chain(h_open(E), current_height)`, i.e. `E·N + 1 < current_height` (upper bound on `E`; it exists so the seal read cannot throw `BLOCK_DNE` on an attacker-chosen future `E`) | `blockchain.cpp:5186–5190` and `:5201` (C++, reachable, per-epoch); the first duplicated Rust-side as `ERR_CREDIT_DEADLINE`, `serve_credit.rs:211–212`, unreachable only because C++ refuses first | **Yes.** The first is *exactly* the gate §12 named; the second is the one the first cut omitted (Copilot, PR #747). Together they admit `E·N + 2 ≤ current_height ≤ (E+1)·N`. |

So: a record for `(P, s, E)` **can** ride a block of `E+1` — its leaf index is
bound to *that* block's predecessor, its `E` is whatever the prover wrote — and
row 5 refuses it **except at one height**: `current_height = h_close(E) =
(E+1)·N`, the first block of `E+1`, where `>` is false and the record is
admitted with `E ≠ epoch(current_height)`. `SO-D8` §12 stands as written.

### `SO-D9` — `ERR_EPOCH_MISMATCH` is a check that cannot fire (filed as its own finding)

`serve_credit.rs:168–169` refuses when `response.settlement_epoch !=
ctx.settlement_epoch`. `ctx.settlement_epoch` is populated at
`blockchain.cpp:5304` from `sc_settlement_epoch` — **the value parsed out of
the same record at `:5124`**. `shekyl_archival_verify_serve_credit_vin` has one
production caller (`:5315`). The check compares the record against a copy of
itself and refuses nothing.

Second instance of rule 50's *"checks that cannot fail"* class in this arc.
Filed in `docs/FOLLOWUPS.md` independently of how `SO-D8` resolves, because a
tautological consensus check is a defect whether or not this round makes it
load-bearing. Two dispositions, one of which is a consensus tightening and is
therefore **Rick's**:

- **(i) Make it fire — RULED as the *rule*; C++ *site* SUPERSEDED 2026-09-16 (Q15).** Records-was of 2026-09-13: populate `ctx.settlement_epoch` from `shekyl_archival_settlement_epoch_at_height(current_height)` (`shekyl_ffi.h:2594`) — one C++ line. **Do not build that line.** The rule lands as a `shekyl-chain-rules` `CenRow` whose operand is the validated issuing `h`; the tautology never ports to C++.
- **(ii) Delete it** and let the row-5 `h_close` gate be the single expression. **REJECTED 2026-09-13** (the quote below).

> **RULED 2026-09-13 — (i).** Rick: *"Deleting leaves the rule implicit in an
> `h_close` comparison, which is a bound on **when**, not a statement that the
> record's epoch is the block's epoch. (i) makes that an explicit single-site
> rule, enforced, using a helper that already exists — and it's the rule the
> derived-assignment cutover needs regardless of which shape R-A or R-B takes.
> One line, and pre-genesis there's no migration to weigh against the
> tightening."* Decision-anchored to this file's ruling commit; folded into
> `ARCHIVAL_SETTLEMENT_WRITER.md` §13 and the `IMPLEMENTATION_INDEX.md` SO row.
>
> Two facts about the site, read for the implementation, not assumed:
>
> - **Ordering — corrected 2026-09-14 (Copilot, PR #747).** *Superseded text:
>   "`EPOCH_MISMATCH` is the live refusal for a header naming a future epoch,
>   which today reaches the FFI."* It does not. **Two** C++ gates run before
>   the FFI call that evaluates `EPOCH_MISMATCH` (`:5315`): `h_close`
>   (`:5188`) refuses `current_height > (E+1)·N`, and `challenge_seal_on_chain`
>   (`:5201`) refuses `E·N + 1 ≥ current_height` — a future-epoch header has
>   `h_open` above the tip and dies there (F1 row 5). What survives to the FFI
>   is `E·N + 2 ≤ current_height ≤ (E+1)·N`, so the **only** header that reaches
>   `EPOCH_MISMATCH` with `E ≠ epoch(current_height)` is the boundary case
>   `current_height = (E+1)·N`: a record for `E` in the first block of `E+1`
>   — the straddler itself. Consequences: (a) with (i) landed on today's path
>   and nothing else changed, that one block flips from **admitted** (the
>   tautology passes) to **refused**; (b) under R-B the operand is the
>   validated issuing block `h` (next bullet) and the same record is admitted
>   again when `epoch(h) = E`, so (i)-alone is a one-block behaviour change
>   the cutover reverses — build them together, or accept the interim flip
>   knowingly (Q14); (c) **SUPERSEDED 2026-09-16 (Q15):** the 2026-09-13
>   coverage plan was an isolated FFI test
>   (`shekyl-ffi/src/archival_ffi/tests.rs` driving
>   `shekyl_archival_verify_serve_credit_vin`). That test cannot cover the
>   new row. The falsifier is a `shekyl-chain-rules` `CenRow` whose
>   negative fixture refuses `settlement_epoch ≠ settlement_epoch_at_height(h)`
>   with typed `InvalidBlock` — not a full-path future-epoch vector, which
>   the seal gate would refuse first and mis-attribute. The cutover that deletes the beacon gates
>   (§2.1 item 1) removes both pre-FFI bounds; after it, `EPOCH_MISMATCH` is
>   the *only* rule relating `E` to a height, which is why it must exist.
> - **What is ruled is the site, not the value's provenance.** Under R-A the
>   value at `:5304` is `settlement_epoch_at_height(current_height)`. **Under
>   R-B (ratified, §2) the same site computes the *issuing* block's epoch,
>   `settlement_epoch_at_height(h)`**, where `h` has first been validated as a
>   real block in the window (§2.1 item 3). The rule "the record's declared
>   epoch equals the epoch consensus assigns to it" is the single-site
>   statement in either case — and under R-B it is a **real** check for the
>   first time, because `h` is validated rather than copied from the record.
>
> **Implementation status: NOT built — and not to be built on the C++
> path.** Q15 (2026-09-16) closes Q14 as (a), stronger: (i) lands **with**
> the R-B cutover as a `shekyl-chain-rules` row whose operand is the
> validated issuing block `h`. A C++ one-liner at `:5304` would be the
> mirroring Q15 refused, and would write the one-block flip the Ordering
> bullet already named. **Prohibition (Q14, 2026-09-16):** do **not**
> repair the tautology in `blockchain.cpp`. Making that check fire is a
> consensus tightening on the live LMDB daemon for a path being replaced,
> on the shorter-lived of the two implementations. In chain-rules it is a
> positive row with a negative fixture; the tautology never ports. The
> FOLLOWUPS falsifier is that `CenRow` fixture. The FFI isolated test is
> **not** coverage of the new row. The full-path vectors (stale → deadline, future →
> seal) die with the beacon gates they live on. FOLLOWUPS row carries it.

### 1.1 What is true about `W₂`, and why it makes the round larger

`CHALLENGE_RESPONSE_BLOCKS` has **no admission consumer in code** —
verified 2026-09-13: `constants.rs:171`, `:183–185`, `:194–195` are
const-asserts and `lib.rs:139` is the re-export; nothing else reads it.
Its doc string — *"blocks after a challenge's issuing block to accept its
serve-credit response"* (`constants.rs:59`) — described a gate that did
not exist. **`SO-D8a` RULED 2026-09-16 is that reader (design); Slice C is
the first code read; the FOLLOWUPS row is discharged.** The implementation
obligation did not vanish with the row — it is STAGED (rule 23) with a
named consumer: §8's admission row (`ERR_CREDIT_DEADLINE` rebinds to the
`W₂` window; evidence item 9) and the FOLLOWUPS `CEN-L8` / Slice C row,
which names the deadline row as the constant's first code reader
alongside the writer. Its value is
`SETTLEMENT_EPOCH_BLOCKS / W2_EPOCH_DIVISOR = 10,000 / 20 = 500`
(`constants.rs:147,:153,:202`) — about 16.7 hours at 2-minute blocks.

This does not shrink `SO-D8`; it removes its escape hatch. §12's argument was
*"the ruled per-challenge deadline already exists and is per-challenge"*, so
the `h_close` gate could simply be re-pointed at it. It did not exist
(2026-09-13). Under
the ratified shape R-B the round must **design** that deadline, not re-point
to it — and the constant then acquires the consumer its doc string already
describes (`SO-D8a` / §3 **RULED 2026-09-16**; the FOLLOWUPS row
**discharged** with that item — first admission-path reader).

`SO-D7`'s lag argument (*"a challenge drawn at epoch-relative block 9,999
resolves 500 blocks into `E+1`"*, `IMPLEMENTATION_INDEX.md` SO row) reads the
same doc string as a mechanism. It describes shape R-B — which is now the
ruled direction, so the sentence becomes true when the cutover lands and is
false until then.

### 1.2 The class, recorded

The first cut framed itself as *"the fourth dissolve-on-grounding in the SO/RF
arc"* (`RF-D3`, the W₂ floor, the Pi-4 question). Those three were real. The
review's point, adopted here: **pattern-matching to them is plausibly how this
one got written.** A round that has logged three constraints dissolving at
source arrives at the fourth expecting a fourth, and reads a check whose
**shape** looks load-bearing (a comparison, an error code, a refusal path)
without reading where its **operands** come from — which is reading the doc
string one level down. A prior in favour of dissolution is not evidence for
it; the class this instance belongs to is *finding what one came to find*, and
it is recorded under that name rather than as a fifth member of the other.

Two operational rules this adds: **for every refusal cited as a binding, name
the source of each operand**; and **when a finding matches a class the round
has already logged three times, that match is a reason to re-check, not a
reason to stop.**

### 1.3 F3 — the first cut conflated two mechanisms' block bindings (corrected at source in F1 row 1)

The first cut's F1 row 1 cited *"nonce `H(block_hash(h−1) ‖ cb_out_key(h) ‖ P
‖ s ‖ E)`, `blockchain.cpp:5504` (`cb_out_key` from `b.miner_tx`), `:5515`
(`b.prev_id`)"* as the serve-credit vin's binding to its block. Those lines
are **`verify_block_attestation`** — the block-level attestation path (coinbase
`tx_extra` `0x0B`, `attestation_root`, P-countersigned witness records,
`attestation_wire.rs:80` `NONCE_INPUT_LEN`), a *different* mechanism that
happens to share `P, s, E` operands. The serve-credit **vin** path
(`blockchain.cpp:5302–5320`) populates `current_height`, `settlement_epoch`,
`block_hash_at_seal`, `prev_block_hash`, `registry_segment_subroot_rk`,
`segment_leaf_count`, the bond pubkey and the leaf layer — **no `cb_out_key`
and no nonce**. Its block binding is F1 row 1 as now written: `prev_block_hash
→ challenge_leaf_index → signed preimage`.

Consequence for R-B (§2.1 item 2): what must rebind to the issuing block is
the **leaf-index derivation** (and the fire-height input dies), not a nonce.
That is one operand, not two, and it is already verifier-derived
(`RF-D6`/`RF-D8`), so the change is *which block's* hash C++ hands the FFI —
not a new wire term. Operand-source rule of §1.2, applied to the first cut's
own table.

### 1.4 F4 — `PC-D2` and `ARCHIVAL_CHALLENGE_MECHANISM.md` §2 contradict each other, and `PC-D2`'s premise is inverted

`ARCHIVAL_PER_CHALLENGE_RECORD.md` `PC-D2` rules *"the block is implicit: the
record rides its own producer's block"* — shape R-A — and gives as its ground
that a claimed-block field is forgeable and that arbitrating a thundering
herd is to be avoided. `ARCHIVAL_CHALLENGE_MECHANISM.md` §2 (the ratified
derived-assignment lifecycle) has the pass record *"broadcast as a
transaction; any miner may include it within the resolution window W₂"* —
shape R-B. Both are ratified text; they cannot both be the mechanism.

**The herd premise is inverted.** Under R-A every miner attempting `h` must
fetch `~λ·D/SEB` segments (≈ 97 at maturity, §7.1) from their `P`s *inside the
block interval*, speculatively, because the record can only ride `h` and only
`h`'s winner gets paid for it. That is ~97 concurrent fetches per pool per
block hitting the same `P`s — the herd `PC-D2` was written to avoid. Under
R-B only the *winner* of `h` fetches, and has `W₂ = 500` blocks (~16.7 h) to
do it: the same 323 MB per epoch spread over hours instead of 120 seconds,
~5.4 KB/s sustained. It is the difference between a duty and a capacity test.
Rick, 2026-09-13: *"the 'thundering herd' problem was actually all the miners
trying to hit a single P while mining, so this is sort of the same problem in
reverse."* R-A is the herd; R-B is its cure.

Disposition: **`PC-D2` is reversed by the R-B ratification (§2)**; the
mechanism doc's §2 lifecycle is the authority; `PC-D2`'s forgeable-field
objection is answered not by a claimed-block field but by **validating `h`**
(§2.1 item 3) — a validated reference is not a claimed value. The reversal is
recorded in `ARCHIVAL_PER_CHALLENGE_RECORD.md` in-line at `PC-D2` when the
ruling PR lands (rule 23: the superseded row carries its status in the row).

### 1.5 F5 — every FCMP++ spend is linkable to the output it spends, by the public 4th leaf scalar (**tree-wide; → `PL-D1`, CLOSED by `PL-D3` in PR #745, 2026-09-14; the table below is the defect as found at `dev@37accf6f`, 2026-09-13**)

**The 2026-09-16 F5 agent brief is WITHDRAWN, not amended.** It instructed
an agent to verify the defect, census the blast radius, correct
`FCMP_PLUS_PLUS.md` / `MERKLE_TREE.md` / `POST_QUANTUM_CRYPTOGRAPHY.md` /
`REWARD_EMISSION_LEG.md` at source, and produce a fix round — against a
round already CLOSED by `PL-D3` (#745, 2026-09-14). Re-deriving it would
rewrite the documents #745 already corrected (the RF-D8 (i) fifth-site
shape). The brief never landed in the tree. The living surface is the
`PL-` index row and `FCMP_SPEND_LINKABILITY.md`. Do not reopen `PL-D3`.
Do not edit the `PL-` row from this lane (rule 94 §6).

Rick asked, before adopting a witness scheme that reveals a coinbase output's
per-output hybrid key early: *what prevents `H(revealed hybrid_public_key)`
from being matched against the chain's published per-output leaf hashes at
spend time? There must be something — otherwise every FCMP++ spend would be
trivially linkable.* Read at source, 2026-09-13: **nothing prevented it, and
every FCMP++ spend was trivially linkable.** The chain, each link verified
at that pin (**records-was**; rows 1, 4 and 5 are the ones `PL-D3` changes):

| # | Fact | Where |
|---|---|---|
| 1 | Every non-coinbase output commits `h_pqc = H(hybrid_public_key)` **publicly** in `tx_extra` `0x07`, one 32-byte hash per output in vout order; the daemon copies it into the 128-byte leaf `{O.x, I.x, C.x, h_pqc}` at `[96..128]`, stored in `curve_tree_leaves` | `FCMP_PLUS_PLUS.md:65,:215–220,:704`; `blockchain_db.cpp:528–556` (`extract_leaf_hashes`); `shekyl-fcmp/src/leaf.rs:38–62`; `CURVE_TREE_CLIENT.md:402–411` (*"fully public (already on the chain)"*) |
| 2 | `h_pqc` is **per-output unique**: `derive_pqc_leaf_hash(combined_ss, output_index)` = `hash_pqc_public_key(derive_pqc_public_key(combined_ss, output_index))`, both from `derive_output_secrets` on the same `(combined_ss, index)`; the coinbase self-encapsulation exists *precisely* to keep them distinct (*"would link rewards"*) | `derivation.rs:87–113,:120–135,:230`; `FCMP_PLUS_PLUS.md:240–247` |
| 3 | The spend carries **that same `hybrid_public_key` in cleartext** in `tx.pqc_auths[i]` | `tx_pqc_verify.cpp:128–129` (serialised into the signed header), `:169–232` (verified as supplied) |
| 4 | Consensus hashes the revealed key with the **leaf-hash function** and hands the result to the FCMP++ verifier as a **public input** | `blockchain.cpp:4348–4356` (`shekyl_fcmp_pqc_leaf_hash(hpk) → pqc_hashes_flat`); `fcmps/src/lib.rs:102–111` (`Input { O_tilde, I_tilde, R, C_tilde, extra_leaf_scalars: "Public values" }`), `:784` |
| 5 | The circuit **blinds** `O, I, C` (`O_tilde = O + o_blind·T` etc.) and then **constrains the leaf's 4th scalar to equal the public value, unblinded**: `constrain_equal_to_zero(var − public_val)`; the membership tuple is `{O.x, I.x, C.x, h_pqc}` with `h_pqc` a public constant | `fcmps/src/circuit.rs:133–163` (blinding), `:153–163` (equality), `:166–168` (tuple) |

So for every input `i` of every FCMP++ transaction, the spent leaf is **the
unique leaf whose bytes `[96..128]` equal `H(tx.pqc_auths[i].hybrid_public_key)`**
— an `O(1)` lookup against a table every node holds, or a scan of `tx_extra`
`0x07` blobs. The anonymity set of every spend is **one**. No circuit break is
needed; the observer never touches the proof — the public inputs are enough.

**The tree's own documentation asserts the opposite**, in three places a
reader would trust: `FCMP_PLUS_PLUS.md:102–104,:121–122` (*"does not reveal
which leaves are spent"*, *"anonymous, zero-knowledge"*),
`POST_QUANTUM_CRYPTOGRAPHY.md:735–737` (*"without revealing which leaf"*),
`MERKLE_TREE.md:235` (*"again, without revealing which leaf"*). All three are
true of `O, I, C` and false of the tuple. Rule 16's corollary in its purest
form: the claim is true of the design's *intent* and false of the design.

**The tripwire already written for this fired and nobody was watching it.**
`REWARD_EMISSION_LEG.md` §7.3 (`:806–829`) found *this exact enumerability*
for the emission backing vin — *"leaf extra-scalars are publicly enumerable,
so this reveal deterministically identifies the backing output"* — and
dispositioned it as safe because *"the creating tx's inputs are
FCMP++-hidden"*, with a **tripwire**: *"Any future change weakening FCMP++
input anonymity (or letting output identification reach a tx's inputs)
reopens this finding."* The creating tx's inputs carry the identical
`pqc_auths` construction. They were never hidden. The tripwire condition was
true when it was written; the analysis was scoped to one vin and did not ask
whether the ordinary spend had the same shape (`FCMP_MEMBERSHIP_ONLY.md:376–384`
cross-references the same disposition). §7.3's *"third linkability class"* is
not a class of the emission vin; it is the tree. *(#745 strikes the §7.3
invariant at source, marks the tripwire FIRED, and removes the emission
vin's `pqc_pk_hash` field — its binding becomes the in-proof opening, `PL`
§12 ruling 9.)*

**Disposition — SUPERSEDED 2026-09-14 by the `PL-` round (#745); the
2026-09-13 text is retained below, marked.** What was proposed here on
2026-09-13 was: file in `FOLLOWUPS.md` as pre-genesis priority-2, mint no
family, Rick opens the round. Rick did, the same day; `PL-D1` is the defect,
`PL-D3` the fix, `PL-D4` (a proper hash-commitment mechanism) the V4
successor. The reconciliation this proposal owes under `PL` §12 ruling 11:

- **The `FOLLOWUPS.md` line is withdrawn** (this branch, 2026-09-14). The one
  line of record is the `PL-` round's `PL-D4` entry under `Target: V4`, landing
  with #745. Nothing `SO-` owns is on it. The `PL-D1` row on `dev`
  (`FOLLOWUPS.md:17`) still carries *"Also filed as `F5` on
  `docs/so-d8-proposal` (branch-only); whichever lands second reconciles"* —
  that sentence is **removed by #745 itself**, which deletes the whole `PL-D1`
  row when `PL-D3` lands (its `FOLLOWUPS.md` diff is `−4/+1`; the row's own
  text says *"this item closes when it lands"*). This branch does **not** edit
  that row: it is the `PL-` lane's (rule 94 §6), and a modify here against a
  delete there is a conflict for whichever PR lands second. Until #745 merges
  the cross-reference is stale-but-harmless (it points at a line that no
  longer exists); after it, gone.
- **What `PL-D3` does, as ratified** (`FCMP_SPEND_LINKABILITY.md` §6.2, read on
  `feat/pl-d3-pedersen-leaf-commitment` 2026-09-14): the leaf's 4th scalar
  becomes `CM.x`, `CM = k·G_k + r·G_r` (two NUMS generators), with `k = H_ℓ(hybrid_pk)` a cSHAKE256
  read under `shekyl/pqc-leaf-key-v1` reduced into the Ed25519 scalar field
  and `r` an HKDF blind from the same `combined_ss`. The circuit opens `CM`
  to the verifier-derived `K = k·G_k` (`shekyl-oxide/crypto/fcmps`
  `first_layer`); the `0x07` entry becomes 64 B, `CM ‖ record`, `record =
  cSHAKE256("shekyl/pqc-leaf-record-v1", pk ‖ r_h)` (`PL-D3a`, the
  post-quantum binding that survives into V4). New consensus content rule at
  relay and connect: every `0x07` point canonical, prime-order, non-identity
  (`check_pqc_leaf_entries`). The wallet verifies both halves at scan;
  mismatch is received-but-unspendable. `hybrid_public_key` stays in
  cleartext at spend — as §1.5's 2026-09-13 text predicted every fix would.
- **Why it fixes `PL-D1`, in the round's own words:** *"`k` (and `K`) appears
  once, at spend, and is published nowhere at creation; `CM` is published at
  creation and is a perfectly hiding commitment, so matching `K` to any `CM`
  requires `r`."* **That sentence is the premise this proposal now builds
  on.** The fix does not hide `K`; it hides *which `CM`* `K` opens to. A key
  that is published a second time, under a second label, is linked by byte
  equality with no commitment involved — which is exactly what a witness
  scheme keyed on a spendable output's own key would do (§2.2).
- **What it is not, unchanged:** not a soundness defect; funds were safe
  throughout. `PL-D2` (the in-circuit binding is only as sound as the
  discrete-log proof) is ruled and documented at source by the same round;
  the post-quantum-sound leg is `PL-D4` at V4.
- **Residual the round records (its §13), and why it does not reach `SO-`:**
  the output's *creator* holds `combined_ss` and can recognise the spend of
  the output it created. For the coinbase, creator and recipient are the same
  party (self-encapsulation), so the residual is empty on the only outputs
  the witness scheme touches.

*Superseded 2026-09-13 text, retained for the record:* filed in
`docs/FOLLOWUPS.md`, `Target: pre-genesis`, priority-2, no family minted,
Rick's to open; not a soundness defect; a fix must convince the verifier the
revealed key matches the leaf without disclosing the 4th scalar (in-circuit
hash, blinded commitment re-randomised like `C`, or a non-per-output key
structure) and every such fix keeps `hybrid_public_key` in cleartext at
spend; genesis-frozen surfaces touched: leaf layout, public-input list,
`tx.pqc_auths`, `tx_extra` `0x07`. The prediction held: `PL-D3` is the
blinded-commitment option, and the key is still in cleartext at spend.

---

## 2. The two shapes, and the one ratified

Neither is "what the tree is". The tree today is the interim beacon: one
challenge per pair-epoch, response accepted anywhere in `(h_fire, h_close]`,
epoch prover-declared. Derived assignment replaces that, and the replacement
must pick one of:

| | **R-A — same-block** (`PC-D2`'s shape) | **R-B — post-issuance window** (`ARCHIVAL_CHALLENGE_MECHANISM.md` §2, `W₂`'s doc string, `SO-D7`, `SO-D8` §12) — **RATIFIED 2026-09-13** |
|---|---|---|
| Record answers the challenge of | the block it rides in: `(P,s) ∈ assignment(h_incl)` and `E = epoch(h_incl)` | an issuing block `h`, `h < h_incl ≤ h + W₂`, **named in the record and validated** |
| How `E` is bound to the block | `SO-D9` (i) from `current_height` | `SO-D9` (i) from **`h`**: `epoch(h) == E` — a real check, because `h` is validated |
| How `h` is identified | it is `h_incl`; nothing to identify | header field `h` (kept side, `117 → ~125` B); validated as a real block in `[h_incl − W₂, h_incl)`. A *validated* reference is not the forgeable claimed value `PC-D2` deleted claimed-block fields for |
| Block operand the leaf index derives from (`PC-D3`) | `block_hash(h_incl − 1)` | **`block_hash(h − 1)`** — the issuing block's predecessor (F3: one operand, verifier-derived, no new wire term) |
| `h_close` gate (`blockchain.cpp:5186`) | stays | **replaced** by the per-challenge deadline `h_incl ≤ h + CHALLENGE_RESPONSE_BLOCKS` (§3) |
| Dedup (`blockchain.cpp:5156`) | pair-epoch-wide `pass_count > 0` is **exact** — one draw per block | **`(P, s, E, h)`** — and the exact-get *resolves* because `h` is in the DB (§4) |
| Emission gather at `h_close(E)` (`db_lmdb.cpp:8334`) | complete | **incomplete** until `h_close(E) + W₂`; moves to the slash pass (§5) — `SO-D7` applied to a second consumer |
| `passes > issued` | unreachable once the membership gate lands | **asymmetric as originally stated** — fires only when `issued` is too low; `issued` too high settles Missed with no detector. Under `SO-D8b` the named inequality is unreachable by construction. Three **local** layers guard Q3 reconstruction instead; the harmful direction is layer 2's alone (persisted digest + re-walk); FATAL retained as a dominated backstop; desync is a store-invariant Fault; on-chain digest **REJECTED** (§6) |
| Who fetches, and when | **every** miner attempting `h`, speculatively, inside the block interval — the herd (F4) | **the winner of `h`**, within `W₂` blocks |
| Who is the witness, and how is that proven | implicit: the record rides the producer's block | the producer of `h`, **authenticated** by a hybrid signature under a key `h` committed (§2.2) |
| Frozen surfaces touched | none on the wire | record format (RF round reopens, rule 21), rule-42 version bump, one new `tx_extra` tag (§2.2) |

**Ratified: R-B.** Rick, 2026-09-13: *"This is the way it needs to work."*
The grounds, in the order they were established: (1) F4 — R-A is the herd,
not its avoidance; (2) `SO-D7`'s finding (*"pass evidence is not final at
`h_close`"*) was already ruled for the writer and simply applies to the
emission gather too — R-B extends a ruling rather than inventing one; (3) `W₂`
acquires the consumer its doc string describes (Q2 resolves as a consequence
of Q1, not independently); (4) the honest new cost — dedup on `(P,s,E,h)` — is
`PC-D4`'s widening one field further, and `PC-D4` already established the
per-pair-epoch fold the emission gather needs. The first cut recommended R-A;
that recommendation is **withdrawn** and the reason it was wrong is F4.

### 2.1 What R-B modifies — eight items

Items **7 and 8 RULED 2026-09-16** (Q10, Q9). **`SO-D8a`/`b`/`c` RULED
2026-09-16** (items 3b/fire, 4, 5 — transcriptions). **`SO-D8d` RULED
2026-09-16** (§6). **`SO-D8e` RULED 2026-09-16** (§7.2). **Q4 RESOLVED
2026-09-17** (item 6's λ pin landed).

Rick's enumeration of 2026-09-13, re-grounded at source; where the tree
disagrees with the enumeration the correction is marked.

1. **Record format — genesis-frozen, and the RF round reopens.** `h` on the
   kept side (varint ≤ 10 B), kept ceiling `117 → 127` worst case
   (`1 + 32 + 10 + 10 + 10 + 64`). That moves `ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES`
   (`cryptonote_config.h:425`), its `static_assert` (`:426`) and the
   const-asserted twin in `shekyl-wire` (`transaction.rs:184,:197`) — three
   sites, one literal. Witness pk + sig go **pruned** (§2.2), so the pruned
   ceiling re-derives (`ARCHIVAL_RESPONSE_FORMAT.md:845` gives 5,107 B
   pre-`RF-D6`, `:974` ~3,411 B after; the new figure is that plus the witness
   material, or plus its amortised share under batching — item 8).
   `attestation_wire.rs`'s kept header is the *attestation* path's, not the
   vin's (F3); the vin header that gains `h` is `ArchivalServeCreditResponse`
   (`wire.rs`). **Rule 42 fires**: persisted block bytes move, version bump
   owed. **Rule 21 reopening criterion for the RF close (2026-08-21) is met**
   — the ruled mechanism changed; this is the substrate change the close
   named, not preference.
2. **The leaf-index operand rebinds to the issuing block** (corrected from
   *"nonce operands"* — F3). `PC-D3`'s `challenge_leaf_index` takes
   `block_hash(h − 1)`, the issuing block's predecessor, in place of
   `prev_block_hash` of the including block; the validator fetches it by
   validated height from `ChainView`. `ctx.block_hash_at_seal`
   (`blockchain.cpp:5305`) and `challenge_fire_height` die with the beacon.
   *2026-09-13 text named an FFI ctx field; Q15 deletes the FFI — `h` is a
   field of the rule's input, not of a C++ context struct.*
3. **Admission path — five changes (semantics 2026-09-13; home SUPERSEDED
   2026-09-16 by Q15).** *Superseded site: `blockchain.cpp:5100–5330`.* The
   five changes land as `CEN-` rows in `shekyl-chain-rules` (§8), not in
   that function:
   (a) parse `h`; validate it is a real block with `h_incl − W₂ ≤ h < h_incl`
   (`h_incl` is the candidate's height = `ChainView` tip + 1 on connect;
   `h = tip` is in range); (b) **replace** the `h_close` gate (`:5186`)
   with the per-challenge deadline — the upper bound in (a) *is* the deadline;
   (c) `SO-D9` (i) as `settlement_epoch_at_height(h) == E`; (d) membership:
   `(P, s) ∈ assignment(h)` — the urn must answer for the last `W₂` blocks,
   not only the current one (§7); (e) witness authentication — read `h`'s
   coinbase witness commitment, compare the hash of the presented witness
   key, verify the hybrid signature over the record's binding preimage
   (§2.2). Order matters for which refusal a test observes; the `SO-D9`
   ruling's ordering note applies.
4. **The dedup key stops being vacuous — an unexpected win.** `PC-D4` widened
   the ledger key to `(P, s, E, block)` but kept dedup pair-epoch-wide
   (`blockchain.cpp:5156` is `archival_serve_credit_pass_count(P,s,E) > 0`)
   because the exact-get would probe a block not yet in the DB. Under R-B the
   key's block is `h`, **in the past and in the DB**, so `(P, s, E, h)` is an
   exact-get that resolves; `PC-D7`'s deferred half discharges without the
   workaround. **Semantic change to record:** the ledger's height field means
   *including* block today and must mean *issuing* block; the 48-byte-prefix
   `pass_count` is unaffected either way.
5. **Emission gather — the real cost, and smaller than billed.**
   `gather_archival_emission_epoch_snapshot` (`db_lmdb.cpp:8334`) at
   `h_close(E)` becomes incomplete: records for `E` land up to `W₂ = 500`
   blocks into `E+1`. It moves to the slash pass
   (`process_archival_slash_for_epoch`, `:6075`, at `h > h_close(E) +
   CHALLENGE_RESOLUTION_BLOCKS = h_close(E) + 10,000`, `constants.rs:44`),
   where **every** record for `E` is final because `10,000 ≥ 500`. This is
   `SO-D7`'s finding applied to a second consumer; the writer round verified
   emission was untouched *only under the beacon*, where records are final at
   `h_close`. Not a new problem R-B introduces — a ruling already made
   arriving at the place its first application verified it did not reach,
   with the verification scoped to a mechanism R-B replaces.
6. **Constants get their referents.** `CHALLENGE_RESPONSE_BLOCKS` becomes the
   per-challenge deadline its doc string (`constants.rs:59`) already
   describes — that reader is `SO-D8a` **RULED 2026-09-16**; the FOLLOWUPS
   row **discharged**. `CHALLENGE_RESOLUTION_BLOCKS ≥ CHALLENGE_RESPONSE_BLOCKS`
   (`:183–185`) becomes load-bearing (item 5 depends on it). `λ` is
   pinned to `CHALLENGES_PER_PAIR_PER_EPOCH` at the urn's entry points
   (Q4 RESOLVED 2026-09-17, §7.3).
7. **New daemon-side secret lifetime — Q10 RULED 2026-09-16 (§7.7): accept
   loss.** The producer of `h` retains the material to sign as witness
   until the batch is included (deadline `W₂`, expected latency much
   shorter). Rust-owned, memory-only, `ZeroizeOnDrop`, rules 35/36.
   Persist-encrypted is **REJECTED** (a daemon has no passphrase; rule 36
   §3 is a wallet envelope). Restart loss is β, logged as dropped
   in-flight count. Named fallback if β is restart-dominated:
   re-derivable `tx_key`, not persist. §2.2 / §7.5 say *which* secret.
8. **Block weight — batching RULED 2026-09-16, amended same day (§7.6): set-commitment carrier, fail-whole, resubmission within `W₂`.** At
   maturity (~97 draws/block; provisional on `D ≈ 324k`) witness addition per
   record is `PQC_HYBRID_SINGLE_KEY_LEN + PQC_HYBRID_SINGLE_SIG_LEN` =
   1,996 + 3,385 = 5,381 B (`cryptonote_config.h:386,:388`) against a record
   that is ~3,411 B post-`RF-D8`-retraction (`ARCHIVAL_RESPONSE_FORMAT.md:1012`).
   Unbatched ≈ 850 KB/block-equivalent; fully batched (one pk + one sig for
   the set) ≈ 335 KB. Ruled form: one pk reveal, one signature over a
   **set commitment** of the carrier's records (§7.6.1); no per-record
   inclusion paths. *SUPERSEDED same day: Merkle-root form with
   ⌈log₂ 97⌉ = 7 hashes, 224 B/record, ~22 KB/block — its isolation premise
   was false under the carrier contract (§7.6.2).*
   Permanent (kept) bytes: ~12 KB/block ≈ 3.2 GB/yr at 120 s/block either
   way. Relayed volume at maturity ≈ 223 GB/yr unbatched vs ≈ 88 GB/yr
   batched, mostly prunable. **Why batch:** at maturity archival traffic
   sets the chain's median, and the fee ladder prices against the long-term
   effective median (`block_weight.rs:10–17`); 850 KB vs 335 KB is a 2.5×
   difference in the baseline every other participant's fees price against.
   **Not** penalty avoidance. **SUPERSEDED:** "against a 300 KB penalty-free
   zone" — 300,000 is `get_min_block_weight` (`cryptonote_basic_impl.cpp:81–85`
   = `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`), a floor; `effective_median`
   is a 100k-block long-term median and a 100-block short-term median clamped
   to `[Mlw, S·Mlw]` (`block_weight.rs:36–39`); sustained archival load raises
   the median and the steady state is penalty-free. **SUPERSEDED:** "who pays
   the fee" (item 8(a) / F3's surviving half) — a serve-credit tx cannot pay
   a fee by construction (`txin_archival_serve_credit_response` is a `txin_v`
   variant, `cryptonote_basic.h:269,315`; coinbase `vin` must be exactly one
   `txin_gen`, `blockchain.cpp:1394–1395`; `archival_tx_kind::serve_credit_only`
   at `blockchain.cpp:3484–3488` is non-spending; `txnFee != 0` is a refusal,
   `tx_verification_utils.cpp:117–119`). Records ride ordinary
   `serve_credit_only` transactions, never the coinbase. **Prunable bytes
   count toward `block_weight`**, read at source before this ruling:
   `get_transaction_weight` is the full-blob size plus Bp+ clawback
   (`cryptonote_format_utils.cpp:323–334`; clawback 0 for serve-credit,
   empty `bulletproofs_plus`); `get_pruned_transaction_weight` reconstructs
   the same number by adding `ARCHIVAL_SERVE_CREDIT_PRUNED_RECORD_BYTES * n`
   (`:374–379`); Rust `Transaction::weight` is `serialized_len() + clawback`
   (`transaction.rs:1457–1466`) and `write` includes the prunable region
   (RF-D1). Two consequences ruled with it: the dedup key stays `(P, s, E, h)`
   per record — a batch is a carrier, not a unit of credit; admission of a
   record proves inclusion in a set that witness authored, not that the set
   was complete. **Carrier is fail-whole** (§7.6.2 (B)): one bad member
   refuses the carrier naming it; the witness refiles without it inside
   `W₂` — a round-trip, not a loss. *SUPERSEDED: "fail-whole refused."*
   **Split under `TX_WEIGHT_LIMIT` (re-derived 2026-09-16):** 42
   records/carrier; 97 draws = 42 / 42 / 13; ≈ 347 KB/block; amortization
   42:1. Cap-raise worth ~11 KB/block ≈ 2.8 GB/year — same fee-and-weight
   round. Three txs are three inclusion decisions: inter-carrier blast
   radius of 42; `W₂` is resubmission headroom. Partition leaks nothing
   (set at `h` is public from `block_hash(h−1)`). Unpaid inclusion of
   zero-fee data, and any discount of prunable archival bytes, belong to
   a fee-and-weight round, not Q9.

### 2.2 Two checks Rick asked for before ruling, and what they returned

**Reorg across `h`/`h_incl` — safe, recorded as checked.** A record at
`h_incl` references `h < h_incl`. A reorg replaces a suffix of the chain, so
any reorg deep enough to remove `h` also removes `h_incl`. There is no
reachable state in which a connected record references a block that no longer
exists; `pop_block` reverting `h_incl` removes the record before `h` can be
touched. Written down because R-B is the first mechanism where evidence and
its reference live in different blocks, and a reader will ask. The cache
(§7) rewinds by the same suffix.

**Linkability of an early witness-key reveal — the answer was F5; under
`PL-D3` (#745) it is `PL-D3`'s own premise, and it rules the key the same
way.** Rick's framing offered two outcomes: *"nothing, because the spend-side
key is re-randomised or distinct"* → scheme clean; *"the pk is sensitive
pre-spend"* → dedicated never-spent witness output. On 2026-09-13 the tree
gave a third: the spend-side key was the same key and its reveal at spend
already identified the output (§1.5). **Under `PL-D3` the second outcome is
the true one, and it is now stated by the fix itself:** the spend-side key is
*not* re-randomised — `pqc_auths[i].hybrid_public_key` is revealed in
cleartext at spend, the verifier derives `K = H_ℓ(pk)·G_k` from it, and the
circuit opens the leaf's hiding `CM` to that `K`. The fix holds **because
`K` appears once, at spend, and is published nowhere at creation** (`PL`
§6.2, "Why it fixes `PL-D1`"). A key published twice is linked by byte
equality, with no commitment in the way:

- **The coinbase output's own per-output key — ruled out, on `PL-D3`'s
  premise.** A witness reveal at `h_incl ≤ h + W₂` publishes that output's
  `pk` labelled *"producer of `h`"*. When the output is later spent, the same
  `pk` appears in `pqc_auths`; equality names the spent input as block `h`'s
  coinbase — anonymity set one for that output, and every coinbase output of
  every block that ever witnessed. `PL-D3` would be intact for the rest of
  the tree and void for exactly the outputs the archival mechanism touches.
  The 2026-09-13 text ruled this out because *"it would leak after F5 is
  fixed"*; that is no longer a prediction — the fix is on record and the leak
  is its stated premise, inverted.
- A **dedicated, never-spent witness output** (Rick's dodge) works but costs
  one extra coinbase output per block — a leaf, a 64-B `0x07` entry (`PL-D3a`),
  a KEM ciphertext (1,120 B) — permanently, for a key that is never used to
  spend; and its `0x07` entry must still pass `check_pqc_leaf_entries` and be
  scan-verified for nothing.
- **Proposed instead, unchanged: a dedicated witness key that is not an
  output.** Derive a hybrid keypair from the coinbase `combined_ss` under a
  **distinct HKDF `info`** — a third child of the same `prk`, beside the
  per-output path and `PL-D3`'s `r`/`r_h` labels; HKDF is registry mechanism 2,
  so like those two labels it is a review duty the count-pin does not cover
  (`PL` §6.2) — and commit the key in the coinbase under a **new `tx_extra`
  tag** (`0x0C` is the next free after `0x0B`; #745 adds no tag). The
  commitment is a **transparent** 32-B cSHAKE256 read of the canonical key
  bytes under its own registered customization (`shekyl/archival-witness-key-v1`,
  a mechanism-1 row, count-pin +1) — **not** `PL-D3`'s leaf-key scalar
  (`shekyl/pqc-leaf-key-v1` is a domain for a scalar that opens a Pedersen
  commitment; reusing it would put a non-leaf key under a leaf domain) and
  **not** a hiding commitment, because hiding buys nothing here: the witness
  role is public by construction (the producer of `h` is the producer of `h`)
  and the key is revealed within `W₂` blocks anyway. 32 B/block permanent, no
  output, no leaf, nothing the spend path ever touches. The witness reveals
  `witness_pk` + a hybrid signature in the record's pruned half; verification
  is (§2.1 item 3e) hash-compare against `h`'s coinbase tag, then verify.
  HKDF children under distinct `info` are independent under the PRF
  assumption the derivation already rests on, so the witness key reveals
  nothing about the sibling per-output key, `r`, or `r_h`. Same
  secret-lifetime cost as any alternative (item 7); the node retains
  `combined_ss` or the derived seed for `W₂` blocks.

**Q8 RULED 2026-09-16 (§7.5): the dedicated non-output key, against
`PL-D3` rather than against the defect.** Commitment home is the new
coinbase tag `0x0C` (the proposal's first cut). **SUPERSEDED:** extending
`0x0B`'s blob instead of minting `0x0C` — the blob is `k × 49` B with no
version prefix, empty = absent tag, and it names records *included in*
this block, not this block *as issuer*. Combined_ss is reachable only
inside Rust `construct_output`; it is not on `ShekylOutputData` and does
not cross the FFI. Pins Q13 and Q10 inherit (§7.5 P1/P2): `0x0C` is
**mandatory-present** (commitment 2, not byte count); per-block uniqueness
of `combined_ss` is a derivation requirement with a fixture, not a KEM
inheritance; Q10 RULED: the `W₂` ring *capacity* is 500, depth tracks
fill-to-inclusion; persist-encrypted **REJECTED**. Q12 RULED (§7.9):
bare 32-byte `cSHAKE256` under `shekyl/archival-witness-key-v1`. Q13
RULED (§7.8): one CEN row, five fixtures, genesis-unconditional; it
does not re-open optionality.

**Q9 RULED 2026-09-16, amended same day (§7.6): set-commitment
batching, carrier fail-whole, resubmission within `W₂`.** One pk, one
signature over a set commitment of the carrier's records; no inclusion
paths. One bad member refuses the carrier naming it; the witness refiles
without it. Dedup stays per-record. There is no fee. The 300 KB figure
is a floor. Prunable bytes count toward weight (read at the weight path,
not inferred from a missing carve-out). The unpaid-inclusion residual is
a fee-and-weight round (FOLLOWUPS row), not Q9. Against
`TX_WEIGHT_LIMIT` the 97-record set splits 42 / 42 / 13 (≈ 347 KB/block;
42:1 amortization). Inter-carrier blast radius is 42; `W₂` is
resubmission headroom. Partition leaks nothing. *SUPERSEDED: Merkle-root
batching with inclusion paths; "fail-whole refused"; 39 / 39 / 19.*

**Q10 RULED 2026-09-16 (§7.7): accept loss.** Memory-only
`ZeroizeOnDrop` ring; persist-encrypted **REJECTED**. File promptly;
evict on inclusion. Orderly shutdown logs remaining depth then drops;
unclean restart logs that in-flight count is **unknown**. Named fallback:
re-derivable `tx_key` from a long-lived node secret and `h`, not persist.

**Q13 RULED 2026-09-16 (§7.8): one `CEN-` row, five fixtures.** Exactly
one entry, length `WITNESS_COMMITMENT_BYTES` (32; Q12 RULED, stays 32
unless a Q12 reopener fires), coinbase only, **present**, from genesis.
Dedicated parser — do not copy `0x0B`'s empty-set convention. First-wins
is the red edit for duplicates.

**Q12 RULED 2026-09-16 (§7.9): bare 32-byte hash.** `cSHAKE256` of the
canonical witness pk under `shekyl/archival-witness-key-v1` (registry
checked, no collision; TSV row at Slice C). Hiding is theater because
the reveal publishes `pk`. The join identifies `h`'s coinbase (stealth
payout already in the block), not a miner identity. Real residual is
P2 / fixture 12. Reopen if `h` is removed **in order to conceal** the
issuing block. Open: Q9 set-commitment vectors (§7.6.1). Q4 RESOLVED
2026-09-17. `SO-D8e` RULED (§7.2); Q9 carrier semantics RULED (B) (§7.6.2).

---

## 3. `SO-D8a` — boundary arithmetic and the deadline gates, under R-B — RULED 2026-09-16

**RULED 2026-09-16: transcription of the R-B ratification.** `E = epoch(h)` —
the issuing block's epoch — enforced by `SO-D9` (i) evaluated at `h`. The
fire gate dies. `h_close` is replaced by the per-challenge `W₂` bound:
`h < h_incl ≤ h + CHALLENGE_RESPONSE_BLOCKS`. A draw at epoch-relative block
9,999 of `E` is answerable in any block up to epoch-relative 499 of `E+1`,
names `E`, and is counted for `E`. Nothing "straddles": the record's epoch is
a function of a validated height. This bound is the constant's first
admission-path reader; the `CHALLENGE_RESPONSE_BLOCKS` FOLLOWUPS row
**discharges** with this item.

The gates at `serve_credit.rs:208–212` and their C++ twins:

- `ERR_FIRE_NOT_REACHED` (`current_height <= h_fire`) — the single-beacon fire
  height (`block_hash_at_seal` input). **Dies with the beacon**; replaced by
  the membership gate (`SO-D8b`) — *"was `(P,s)` drawn at `h`?"* is the only
  fire question derived assignment has.
- `ERR_CREDIT_DEADLINE` / C++ `h_close` gate — **replaced**, not relaxed. The
  first cut kept both as defence in depth *under R-A*; under R-B the gate's
  subject changes from *"before the epoch closes"* to *"within `W₂` of the
  draw"*, and keeping the old bound alongside would refuse exactly the
  records R-B exists to admit (draws in the last `W₂` blocks of `E`). Both
  twins (`blockchain.cpp:5186`, `serve_credit.rs:211`) move to the new
  bound together; the Rust twin stays a defence-in-depth duplicate of the
  C++ rule, in that relationship.
- `ERR_EPOCH_MISMATCH` — `SO-D9` (i), operand `settlement_epoch_at_height(h)`.

Consensus-visibility: three admission changes (`SO-D9` (i), membership, the
deadline re-bound) plus witness authentication. All belong to the §8 atomic
cutover.

## 4. `SO-D8b` — dedup and the membership gate, under R-B — RULED 2026-09-16

**RULED 2026-09-16: transcription.** Dedup widens to `(P, s, E, h)` exact-get;
membership against `assignment(h)`. The exact-get resolves here because `h`
is in the past and in the DB, which is what `PC-D4` could not do.

- Dedup today (`blockchain.cpp:5156`): one serve-credit vin per `(P,s,E)`
  **per epoch** — pair-epoch-wide, `pass_count > 0`. Correct under the beacon
  (one challenge per pair-epoch). Under derived assignment with `λ = 3` draws
  per pair-epoch it would refuse the second and third honest passes, so it
  **must** widen. The widened key `(P,s,E,h)` exact-gets against the `PC-D4`
  ledger whose height field now means *issuing* block (§2.1 item 4) —
  **resolves because `h` is in the past and in the DB**, which is what
  `PC-D4` could not do. Two
  records answering different draws of the same pair may share `h_incl` and
  both admit. Mirror in `serve_credit_decisions.rs` in lockstep.
- **Membership gate, consensus-visible:** admitted only if
  `(P, s) ∈ assignment(h)`. Without it a miner colluding with `P` includes
  pass records for `P`'s pair citing any `h` it likes — regardless of whether
  the urn drew the pair at `h` — and settles **Served** with zero honest
  draws. With it, plus witness authentication, a collusive pass costs *a won
  block at an assigned height* **and** that block's witness key, which is the
  2-of-3 quadratic's pricing assumption.
- Cost: answering `(P,s) ∈ assignment(h)` for any `h` in the trailing `W₂`
  window needs the urn's per-block draws retained for `W₂` blocks, **including
  across the epoch boundary** — a record arriving at `h_incl` can cite an
  `h` in the previous epoch. That window is `SO-D8e`'s structural claim;
  `SO-D8b` is unimplementable without it. See `SO-D8e`.
- **Authority, stated (review 2026-09-16):** `SO-D8b` is RULED as to the
  **key and predicate** — what admission checks. Its implementation is
  STAGED behind `SO-D8e` — how `assignment(h)` is served for a past `h`
  — RULED 2026-09-16 (§7.2: the `W₂` ring).
  Rule 23: a staged item with a named consumer in a live plan, not a
  silent deferral; the two are not independent, and only one of them is
  a design decision still to make.

## 5. `SO-D8c` — emission gather, under R-B — RULED 2026-09-16

**RULED 2026-09-16: transcription of `SO-D7` applied to a second consumer.**
The gather moves from `process_archival_epoch_close_at_height`
to the slash pass, alongside the settlement writer. At `h_close(E)` the
table is incomplete by up to `W₂` blocks of records; at the slash deadline
`h_close(E) + 10,000` it is final. `PC-D6`'s fold (one credit per pair-epoch,
`db_lmdb.cpp:8195` in the writer doc's numbering) is unchanged in shape and
re-keyed over the widened ledger. `REWARD_EMISSION_LEG.md` §4.5 already reads
`Σwork(E)` lagged (*"settlement epoch `E+1` or later"*), so the consumer side
tolerates the move; what changes is **where the snapshot is taken**, and the
`ARCHIVAL_CONSENSUS_STATE.md` §4 invariant-2 joint pin that materialises it
at `h_close` must be re-pinned to the slash pass in the same change.

**Noted, not opened:** emission credits on *presence* (`≥ 1` pass) while
settlement slashes on absolute-2; `PC-D6` says *"no economic disposition
opens"* and this proposal does not open one.

## 6. `SO-D8d` RULED 2026-09-16 — three local layers, none of them on chain; amended same day against `dev@5fde3b1ce`

**RULED 2026-09-16; amended 2026-09-16** after examination against
`dev@5fde3b1ce` (#761, #762, #764 merged). The check is not
`passes > issued` as an accounting alarm. Under `SO-D8b` that named
condition is unreachable by construction: one record per `(P, s, E, h)`
by exact-get, each `h` tied to a draw by the membership gate,
`E = epoch(h)` by `SO-D8a`. So `passes ≤ issued` is not guarding
arithmetic. All three layers guard **Q3** — whether the drawable-set
reconstruction is stable between admission at `h_incl` and settlement at
the slash deadline, hundreds of blocks later. That rationale is written
at the site (`SettleError`, this section, the writer caller).

### 6.1 Which direction costs a bond, and which layer sees it

The fold is absolute-2 on `passes`; `issued` only gates
`NonObservation` (`issued < 2`). So a wrong `issued` matters in exactly
two cases, and `passes > issued` sees neither:

- **Over-derived** — `issued_true < 2 ≤ issued_derived`, `passes < 2`. A
  pair that should settle `NonObservation` settles **Missed**, and an
  archiver who served correctly accumulates a bad observation toward a
  slash. When `passes ≥ 2` an over-derived `issued` is harmless — the
  fold returns Served regardless.
- **Under-derived** — `issued_derived < 2 ≤ issued_true`. A pair that
  should settle **Missed** settles `NonObservation`: the free-exit
  direction `SO-D1` exists to close. `passes ≤ 1 ≤ issued_derived`
  holds, so layer 3 is silent here too.

Layer 3 fires only when `passes ≥ issued_derived + 1`, which requires
records, which layer 1 already covers. **Layer 3 is strictly dominated**
— retained as a cheap backstop, never as the guard.

Layer 1 compares records to assignments pair-by-pair. An over-derived
`issued` produces records that *agree* with the writer's `assignment(h)`
at every `h` a record names; the divergence is in the **count of draws**,
not in whether any particular `h` was drawn. So **layer 1 structurally
cannot see the harmful direction.** The security-priority direction —
both the wrongful slash and the free exit — rests on **layer 2 alone**.
That is why the amendments in §6.3 are load-bearing, not polish: as
first recorded, layer 2 had no operand (§6.3, finding 1), and the only
clause that matters had no working guard.

### 6.2 Three layers, none on chain

1. **Per-record assignment equality.** For each record the writer reads
   at `(P, s, E, h)`, verify that the writer's own `assignment(h)` names
   `(P, s)`. The record is evidence of what admission believed; this
   compares the two derivations directly rather than a consequence of
   them. Catches admission-side defects (a membership gate that let a
   non-member through, a λ that differed between the two doors — §6.5).
   Streamed: replay `ChallengeUrn::advance_block` against the epoch's
   records grouped by `h`, `O(97 × 40 B)` resident — **not**
   `assign_epoch`'s materialised `Vec<Vec<DrawablePair>>` (≈ 39 MB at
   maturity before overhead; rule 76, the Pi 4 is the floor).
2. **Local drawable-set digest.** The node digests `D` when it first
   builds it at `h_open(E)`; the writer **re-walks `D` from the journals
   at every slash pass** (§7.4's enumerator, `O(holdings changes since
   h_open)`) and compares. Catches reconstruction drift, including for
   pairs with **no** records, which layer 1 cannot see. Local only: no
   wire field, no consensus surface, no validity coupling — the cell is
   written, never read by validation.
3. **`passes ≤ issued`, FATAL, never clamped** — retained beneath both as
   a cheap backstop. `settle_epoch` (`attestation.rs`) already returns
   `SettleError::MorePassesThanIssued`; `SettlementRow::settle` refuses
   to compose a row.

### 6.3 Amendments of 2026-09-16 (examination against `dev@5fde3b1ce`)

1. **The digest is persisted — one local 32-byte cell per epoch.** As
   first recorded the digest had no operand: `SO-D8e` said the cache is
   never persisted, and on the resident path the writer's `D` *is* the
   cache's `D` (a digest compared to itself), while on the restart path
   the original digest was lost with the cache (nothing to compare
   against). The cell is written **in the connect batch at `h_open(E)`**,
   so it is undo-logged (SI-6 shape) and therefore reorg-safe for free —
   a pop below `h_open(E)` removes it with the block, which also closes
   the reorg-across-`h_open` staleness a local digest otherwise shares
   with the rejected on-chain one. Not on the wire; never read by any
   rule. `SO-D8e`'s "never persisted" carries this one carve-out
   (§7.2). Not an `SO-D3` violation: a checksum of a derivation is not
   stored state, and it is the only way "compare at settlement" has an
   operand.
2. **Layer 2 re-derives at every slash pass — option (b) — and that
   collapses Q7.** Layer 2 needs two operands: something to compare *to*
   (the persisted digest) and something to compare (a re-derivation). A
   resident cache supplies neither. So the re-walk is not a cost bolted
   on; it is what makes layer 2 exist. Once the writer re-walks at every
   slash pass, retaining the cache past `h_close(E) + W₂` buys nothing at
   settlement, which was its whole justification — so **Q7 drops from
   "retain through the slash deadline" to "drop after `h_close(E) + W₂`"**
   as a consequence, restoring the pure-function property `SO-D1` §4.2
   and `SO-D6` rest on (the writer at `h_slash` is a function of chain
   data, not of what this process happened to keep resident). Layer 1
   then always replays (1.09 s here; Pi-4 owed), inside connect phase 9
   once per epoch — off the admission path, on the connect path once
   per 10,000 blocks. **Conditional on §7.4's churn benchmark.**
   **Stated fallback (a):** if the backward walk proves too expensive
   for the floor device inside connect, layer 2 compares only when the
   cache is non-resident (after a restart) and Q7's retention returns.
   The benchmark number is the falsifier; do not discover the fallback.
3. **Pin 4 reconciled — same refusal, two dispositions, by call site.**
   §7.4 pin 4's "capability limit, not a defect and not a verdict" is
   right *at the enumerator during ordinary operation*: a below-horizon
   request is refused and the caller lives. At the slash pass the same
   refusal means the node cannot settle an epoch it is obligated to
   settle, and skipping is forbidden — so it **escalates to the Fault**
   (§6.4). The call site is what distinguishes them.
4. **Direction analysis** — §6.1 (the harmful direction is layer 2's
   alone; layer 3 dominated).
5. **λ is a fourth falsifier class** — §6.5; and a precondition on Q4.
6. **Ground (3) of the on-chain rejection WITHDRAWN** — §6.6.
7. **Layer 1 streams** — §6.2 item 1.

### 6.4 Disposition at the site: a store-invariant Fault, never a verdict

`dev@5fde3b1ce` already has the vocabulary. `shekyl-chain-rules`
`view.rs:19–23`: a `Fault` is handed back *outside*
`Result<ChainValid, InvalidBlock>` and the caller halts; a refusal is a
verdict that names a `CenRow`. `shekyl-chain-store` `store/halt.rs:12`:
a halt fires when *"a validator hole let something through a belt"* —
layer 1 verbatim — and `ConnectState::Halted { at_height, row:
StoreInvariant }` (`:37–41`) is in memory, re-derived on restart, never
persisted, reads stay open, armed by `poison().arm(row)`.

**An `SO-D8d` desync is therefore a store-invariant Fault carrying a new
`SI-` row, minted at Slice C in `STORE_INVARIANT_REGISTER.md` — never a
`CenRow`, never `InvalidBlock`.** Same posture as the urn's `FeedError`:
a typed refusal from the fold, the poison latch at the slash-pass caller,
never a panic, never a clamp, never a skip.

**The connect phase-9 nuance, stated so it is not "fixed".** The slash
pass runs inside the connect batch (`connect.rs:31,:417`, `[E4 hook]
accrual row, slash, epoch close`). A poisoned batch means **the block at
the slash height is not written on this node — because the writer
halted, not because the block is invalid.** Other nodes connect it. The
old `SettleError` text — "must reject (the block, upstream)" — was
written when the writer ran inside `add_block`; there is no verdict to
issue here, and the records were admitted and connected long ago.

**Forbidden explicitly: clamping, and skipping.** Skip writes no row;
absent reads as NonObservation (`SO-D5`'s inversion), which is the most
forgiving outcome available — a clamp by omission, and the one that will
arrive as a quiet `continue`.

### 6.5 Falsifiers — four classes, named at the site

Each is a different real defect; name them so a later sweep does not
read an unreachable check as dead:

- **revert the `SO-D8b` dedup widening** (back to pair-epoch-wide
  `pass_count > 0`) — layer 1 / layer 3;
- **perturb the drawable-set reconstruction** so admission and
  settlement disagree — layer 2 (and layer 1 if any record's `h` moves);
- **prune a journal above the retention horizon** — fires **upstream of
  the layers**, as §7.4 pin 4's refusal or SI-7 `CellCorrupt { fault:
  Absent }` on the view read, and escalates to the Fault at the slash
  pass (§6.3 item 3);
- **λ divergence between the two doors** — **RESOLVED 2026-09-17**
  (`fix/so-q4-pin-lambda`): `assign_epoch` feeds `ChallengeUrn::new`;
  that constructor reads `CHALLENGES_PER_PAIR_PER_EPOCH`; the
  explicit-λ constructor is `#[cfg(test)]`. A production module in this
  crate cannot pass a coverage that disagrees with the settlement
  threshold. *Records-was:* Q4 named two independent `pub` λ parameters
  (`assign_epoch`, `ChallengeUrn::new`); a λ that differed between them
  left the pair set identical so layer 2 passed and only layer 1 fired
  on replay — a coverage precondition for `SO-D8d`, not only
  correctness. The first landing made the doors `pub(crate)`, which
  still left every non-test module in the crate able to pass a
  divergent λ. Retained as the named falsifier for a `cfg(test)`
  constructor compiled into production.

### 6.6 REJECTED: an on-chain digest of `D` at `h_open(E)`

Complete and symmetric, 32 bytes per epoch — refused on **four**
grounds. (1) It converts a one-row accounting error in a four-journal
backward reconstruction into a chain split. (2) `h_open` is publicly
predictable, so any off-by-one in the reconstruction becomes a fork
trigger an attacker can fire on a schedule for one transaction.
(4) A reorg across an epoch boundary re-judges every record admitted
since `h_open`. (5) Decisively, the inter-node case is already caught by
consensus — a node with the wrong `D` admits records others reject,
which is a fork the ordinary machinery detects. The digest's only
addition is detecting it a few blocks earlier, and that is what all the
rest would be paid for.

**Ground (3) WITHDRAWN 2026-09-16** — *"it makes block validity depend on
journal retention, locking out pruned nodes."* The slash pass is
consensus-visible and every node runs it, so reconstruction back to
`h_open(E)` at `h_slash ≈ h_open + 20,000` is already a participation
requirement, on the local design as much as the on-chain one; the
journals are already outside `prune_archival_epochs_before` (§7.4). The
difference between the two designs is *timing*, which is weak, and
*fork versus local halt*, which grounds (1), (2) and (5) already carry.
Withdrawn rather than softened, so the rejection is not re-argued on
the wrong ground.

**REJECTED, so it is not re-proposed: counting `issued` from records
instead of deriving it.** `SO-D1` §4.2 refuses it — an absent record
would read as never-issued, which is the free-exit hole the scheme exists
to close.

### 6.7 Fixture, and what is carried elsewhere

**Fixture.** Not a unit test of `settle_epoch` — that returns the error
trivially and proves nothing. Seed an admission-side urn from `D` as
built at `h_open` and a settlement-side urn from a `D` **re-walked from
divergent journals**, and show the fold refusing through the Fault path.
That is also the only end-to-end test that Q3's reconstruction and the
admission path are looking at the same object — and it must run the
re-derivation, not the resident cache, or it tests nothing (§6.3 item
2). Lands with Slice C; `attestation.rs`'s existing
`MorePassesThanIssued` unit test stays as the layer-3 mapping pin, not
as this fixture.

**Carried elsewhere, not this item:** serving the epoch's drawable set as
a **served artifact** a pruned node fetches the way it fetches segment
data. Wrong tool for `SO-D8d` (it does not close the local reconstruction
hole without becoming a consensus surface). It addresses the
reconstruction burden that §6.6's withdrawn ground (3) now states as a
participation requirement on every node, and belongs on record against
PDM — do not mint a `PDM-` id here (rule 94 §6).

*SUPERSEDED: "`passes > issued` is the check"; "FATAL means reject the
connecting block"; "the edit that makes it fire is only reverting the
dedup widening"; on-chain `D`-digest; skip-as-continue; "retain the cache
through the slash deadline" (Q7, collapsed by §6.3 item 2); "three edits
make these layers fire" (the pruned-journal edit fires upstream); the
five-ground rejection (ground 3 withdrawn).*

## 7. `SO-D8e` RULED 2026-09-16 — the `EpochAssignmentCache`

### 7.1 Two consumers, two cadences

| Consumer | Question | Cadence | Cost if answered by pure replay (`assign_epoch`) |
|---|---|---|---|
| Admission (`SO-D8b`) | `(P,s) ∈ assignment(h)`, for any `h` in `[h_incl − W₂, h_incl)`? | **every block**, up to ~97 lookups | replay from `h_open(E)` to `h`: `O(draws so far)` — at maturity up to 972,000 cSHAKE draws **per block** |
| Settlement writer (`SO-D1`) | `issued(P,s,E)` for every pair | once per epoch, in the slash pass | one full replay: 972,000 draws |

Measured 2026-09-13, release, this host (`measure_full_epoch_replay_cost_at_maturity`,
`challenge_assignment.rs:534–556`): **1.09 s for 972,000 draws.** Per rule 76
the provisioning floor is the Pi 4, not this host; the Pi-4 figure is **owed**,
not estimated here. Even at this host's speed, ~1 s of pure derivation per
block on the admission path is not acceptable; per epoch in the slash pass it
is.

### 7.2 `SO-D8e` RULED 2026-09-16 — a forward urn, a `W₂` ring, no checkpoints, one set live

**What.** The structure, lifetime, persistence and rewind of the derived
assignment state that `SO-D8b`'s membership gate, `SO-D8d` layer 2, and
Q3's seed all depend on.

**Why.** `SO-D8b` needs `assignment(h)` for any `h` in
`[h_incl − W₂, h_incl)` — 500 blocks back, across an epoch boundary.
`ChallengeUrn` is a sequential stream, so answering a past query naively
means replaying from `h_open`: 1.09 s, on the admission path, per record.
And `assign_epoch`'s full materialisation is ~39 MB of
`Vec<Vec<DrawablePair>>` at maturity, on a floor device (rule 76).

**Rust owns the urn; nothing else does.** `ChallengeUrn` already is the
sequential form (`advance_block(prev_hash)` per block, `draws_done()`;
`challenge_assignment.rs:131–255`). The wrapper is a type in
`shekyl-archival-retention`, no new crate:

```text
EpochAssignmentCache  (derived state; NEVER persisted — SO-D3 derive-don't-store;
                       one carve-out: the 32-B digest of D, written in the connect
                       batch at h_open(E) — item 5 below; undo-logged, never read by a rule)
  open(E, DrawableSet::at_epoch_open(view, E))   // Q3 RULED; λ = CHALLENGES_PER_PAIR_PER_EPOCH read at the entry point (Q4); ONE set live
  advance(h, prev_hash) -> &[DrawablePair]      // assignment(h); pushed onto the ring
  is_assigned(h, P, s) -> bool                  // admission gate; O(1) for any h in the trailing W₂ ring; refuse-not-guess outside it
  rewind_to(h)                                  // pop: truncate the ring; replay the urn forward from the wave boundary at or below h
```

**The design — five items.**

1. **Forward-advancing urn plus a `W₂` ring of outputs.** The urn advances
   as blocks connect, which happens anyway. Keep 500 blocks of assignment
   outputs: `97 × 500 × 40 B ≈ 1.9 MB`. The membership gate reads the ring
   — `O(1)`, nothing on the admission path. An `h` outside the ring is a
   **refusal**, never a replay: the deadline gate (§3) has already refused
   anything older than `W₂`, so the ring's depth and the deadline are the
   same constant and are read from the same place.
2. **No checkpoints. Replay from the wave boundary.** `advance_block`
   resets `working` to canonical order at `remaining == 0`
   (`challenge_assignment.rs:224–230`), so each wave is an independent
   selection-without-replacement from a known state. Zero checkpoint
   state, zero snapshot memory, no cadence to tune. *SUPERSEDED:
   `checkpoint()`; "a reorg deeper than the retained checkpoints."*
3. **One `DrawableSet` live, not two.** The ring holds self-contained
   `(p_id, shard_id)` pairs, so `E`'s set drops at `h_close(E)` and only the
   **ring** spans the boundary. Settlement rebuilds `E`'s set from the
   journals under `SO-D8d` §6.3 item 2. *SUPERSEDED: "holds two
   `DrawableSet`s during the overlap" (§4, §9, the R-B table) — the
   overlap is real, the second set is not; the ring carries it.*
4. **Lifetime `[h_open(E), h_close(E) + W₂]`**, then dropped. Settlement
   does not read the cache; that is what gives `SO-D8d` layer 2 two
   operands (Q7 collapsed, §6.3 item 2).
5. **One carve-out to "never persisted": the 32-byte digest** of `D` at
   `h_open(E)`, written in the connect batch, undo-logged via SI-6,
   reorg-safe for free. No wire field, never read by validation, and safe
   in the batch: the only store-wide digest, `digest_v0` (DRS-P0d), folds a
   fixed family list and **deliberately excludes** the archival journals and
   "every other table" (`digest_v0.rs` module docs), so a new local cell
   does not perturb it; the rule-42 schema snapshot moves, as any new table
   does.

**Memory at maturity:** pairs `324k × 40 B ≈ 13 MB` + working list
`324k × u32 ≈ 1.3 MB` + ring `1.9 MB` ≈ **16 MB**. Against `assign_epoch`'s
~39 MB materialisation, and on the floor device.

**Ordering hazard, named:** the cache is advanced with the *validated*
predecessor's hash, never `prev_id` as supplied on an alt path — the same
constraint `RF-D5` states for the attestation path's `prev_block_hash`.

**Precedent:** `ArchivalSealHashCache` — derived, in-memory, rebuilt from
chain on restart, the pattern `SO-D3` named. **Restart mid-epoch:** rebuild
`D` from the journals (§7.4), replay from `h_open(E)` on first use,
refill the ring for the trailing `W₂` — bounded by one epoch, 1.09 s here.

#### Reorg — closed, two bounded paths

- **Fork at or above `h_open(E)`** — `D` is untouched. `h_open`'s own
  contents cannot change it in either direction, verified at source: a bond
  posted there has `E_join = E` and `E_first = E_join + 1` excludes it
  (`serve_eligibility.rs:8–18`); a **re-bond** there opens its interval at
  `E_reinstate + 1` (`db_lmdb.cpp:6959–6987`), excluded the same way; **drops**
  do not remove pairs (Q3 §7.4 (3.1)); a **release** clears nothing that
  was held — an `Exited` record already holds no shards
  (`db_lmdb.cpp:6626–6627`, "v6 coupling"); and a **slash** applied at an
  epoch-open height is the slash pass's deterministic function of
  settlement rows complete since `h_close + W₂`, ≥ 9,500 blocks below any
  fork there, so both branches remove the same shard. Replay the urn
  forward from the wave boundary at or below the fork, truncate the ring.
  Bounded by one wave: ~324k draws, ~0.36 s.
- **Fork below `h_open(E)`** — possible only in the first 720 blocks of an
  epoch (`ARCHIVAL_REORG_DEPTH_BLOCKS = 720` against `SEB = 10,000`: 7.2 %).
  Rebuild `D` from the journals, rebuild the urn from `h_open`, rewrite the
  digest — the batch undo already rewinds the old one. When the fork lies
  in `E − 1` (the tip is inside `E`'s first 720 blocks), `E − 1`'s tail is
  reconnected on the alt suffix too: rebuild `E − 1`'s `D` (one more §7.4
  walk) and replay its last wave from the wave boundary at or below the
  fork, so the ring entries for those heights are recomputed. Same bound,
  applied twice.

**Wave boundaries are hash-independent** — `done` advances on the
Bresenham schedule `⌊(h+1)·total/E⌋` (`due_through`,
`challenge_assignment.rs:196–204`), a function of block index alone — so
a reorg never moves one and the anchor is always valid.

**Records survive reorgs and are re-submittable verbatim.**
`assignment(h)` binds `block_hash(h−1)`, so every assignment at `h ≤ fork`
is untouched. An orphaned record carries the same `h`, nonce,
countersignature and witness signature, so the archiver does not
re-serve, `P` does not re-sign, and the witness does not re-fetch 3.33 MB.
`W₂ = 500` against a 720-block ceiling is the headroom that makes
re-inclusion work.

**Pin for Slice C (verified-shape, not a design choice):** the instant
`D` is taken at is the same instant `archival_bond_holds_shard_of(·, h_open(E))`
answers for — the two must share one convention (state after block
`h_open(E)` connects, including its phase-9 slash pass), because the
settlement filter (3.3) and the seed are the same predicate at the same
height. Fixture: a slash applied at `h_open(E)` removes the pair from
both, or from neither.

#### Foreclosed, with reasons on record

**Stateless per-block draws with replacement.** It would delete this
entire disposition — pure `assignment(h)`, no ring, no replay, no rewind
— and it is memoryless, so unlike the wave structure it leaks no timing at
all. Refused on three grounds: ~20 % of pairs unobservable per epoch at
`λ = 3` (`P(draws < 2) = e^{−3}(1 + 3) ≈ 0.199`, not the 5 % first
quoted), ~25 % longer time-to-slash, and decisively it invalidates the
absolute-2 ratification, since two passes required from exactly two
draws and two passes required from six draws are not the same test.
Matching exact-λ coverage would cost roughly double the witness fetch
load.

**Known property, recorded not fixed:** without-replacement leaks a
widening warning window at each wave's tail — `P(next draw is me) =
1/remaining`, publicly computable, so a still-undrawn pair late in a wave
can anticipate its challenge. Relevant to the `TJ` free-rider case. Not
grounds to reopen the urn.

#### Owed

- **`SI-` row for `SO-D8d`'s Fault: a new row, `SI-10`.** Checked against
  `STORE_INVARIANT_REGISTER.md` on `dev@5fde3b1ce`: rows **SI-1 through
  SI-9 all exist** — `SI-5` is present and *ruled, unbuilt* (after a pop
  trims the tree to `h`, its root equals the recorded root at `h`), which
  is why it has no `StoreInvariant` variant yet. Reuse refused: `SI-5`'s
  subject is the curve tree, not settlement. The row is minted in the
  register by the Slice C PR that arms it (rule 94 §6 — the DRS lane owns
  the register); this record reserves nothing there.
- **`D_max` ≠ `ARCHIVAL_REORG_DEPTH_BLOCKS`.** 720 is the archival reorg
  depth (`build.rs`, from the economics config); `D_max` is `PDM-Q11`'s
  constant, and `PDM-Q-F24` exists because a ruling already inherited it
  wrongly once. This record uses 720 explicitly and does not name `D_max`.

**No FFI. SUPERSEDED 2026-09-16 (Q15).** *Superseded text: "one opaque
handle, five entry points … C++ marshals heights … In the redb store this
FFI does not exist."* The five-call adaptor was the C++ mirroring Q15
refused. `EpochAssignmentCache` is called from the Rust apply/pop path
only (`DAEMON_REDB_STORE.md` S-CHAIN-W / S-ARCH). It is designed for that
caller; nothing is listed on a deletion surface because nothing temporary
is written.

*SUPERSEDED in this section: "Proposed shape … with checkpoints";
`checkpoint()`; "two `DrawableSet`s during the overlap"; "a reorg deeper
than the retained checkpoints replays from `h_open(E)`"; "retaining
through the slash deadline is the recommendation" (Q7).*

### 7.3 Inputs the shape needs

- **`DrawableSet::at_epoch_open(view, E)` — RULED 2026-09-16 (Q3, §7.4).**
  *Superseded: "no enumerator exists in the tree."* The set the urn is
  seeded with is a pure `shekyl-chain-rules` function over a `ChainView`
  projection of the append-only bond journals, evaluated at `h_open(E)`.
  No snapshot table. Body lands with Slice C. Freeze point is `h_open(E)`,
  not the seal (Pin 5, already ruled).
- **`λ` — RESOLVED 2026-09-17 (Q4, `fix/so-q4-pin-lambda`).**
  `ChallengeUrn::new(pairs, epoch_blocks)` reads
  `CHALLENGES_PER_PAIR_PER_EPOCH` and takes no λ. `assign_epoch(pairs,
  prev_hashes)` feeds that constructor — one production site, so the
  one-shot cannot diverge from the streaming urn.
  `EpochAssignmentCache::open` inherits the same shape. The explicit-λ
  constructor (`with_lambda`) is `#[cfg(test)]` (`pub(crate)` under
  test) for λ ∈ {0, 1, 2, `u32::MAX`}; there is no
  `assign_epoch_with_lambda`. The 972,000 maturity figure is derived
  from the constant in the measurement test, not typed. Pinned by
  `production_doors_read_the_constant_and_take_no_lambda`. Reopen a `pub`
  sim-facing door only for a named out-of-crate consumer (none exists; the
  sim uses the constant analytically). *SUPERSEDED: "a bare `u32` parameter
  at `:152` / `:264` … nothing connects it to the urn … must be pinned
  before any production caller"; the FOLLOWUPS `lambda_target` row
  (removed).*
- **The witness commitment** (§2.2) — a new coinbase `tx_extra` tag and its
  derivation domain. Neither exists.

### 7.4 Q3 RULED 2026-09-16 — the enumerator

`assign_epoch(pairs, prev_hashes)` (`challenge_assignment.rs`, λ from the constant since Q4)
consumes the set of `(p_id, shard_id)` pairs eligible for challenge in epoch
`E`. **Q3 is what produces that vector:** from which tables, evaluated at
which height, under which rule.

**Why it is load-bearing.** `total = λ_target · D` and the Fisher–Yates
working list is indexed over `D` (`challenge_assignment.rs:166–176`). Two
nodes with different `D` produce different assignments for every block of
the epoch. That is a chain split, not a bad challenge.

`ARCHIVAL_SHARD_FETCH.md` is RULED and CLOSED (PR #714) and consumes "the
drawable snapshot at epoch open" with no producer anywhere in the tree:
SF-D5 (`:160`, endpoint key joined by `p_id`), SF-D10 (`:1198–1202`,
holder set of `s`, organic scheduler), RF-R1's reopen (`:180`, the 3.33 MB
whole-shard fetch the witness now skips). The producer is this section.

#### Already ruled — verified, not re-litigated

- Drawable in `E` iff the pair held the shard at `E`'s open; a mid-epoch
  add is not drawable until `E+1`. Freeze point is `h_open(E)`.
  (`ARCHIVAL_CHALLENGE_MECHANISM.md:270–272`, Pin 5.)
- Canonical order: strictly increasing by `(p_id, shard_id)`, `shard_id`
  numeric, explicitly **not** little-endian wire order; construction
  rejects violations (`challenge_assignment.rs:20–28`, `:161–165`).
- `E_first = E_join + 1` (`serve_eligibility.rs:8–18`).

#### This session

**(3.1) A drawn pair whose shard has been dropped is not challenged — but
stays in `D`.** The draw happens. The index space is untouched. Every node
computes the same assignment. Only the expected response changes.

Do **not** remove such pairs from `D`. That is the failure this ruling
exists to prevent — see the drop-stability finding below.

Why the slash outcome does not matter — **corrected 2026-09-16 (review).**
Under (3.3) the drop epoch writes **no row** for the pair (not held at the
fire height), so absence reads NonObservation and the drop contributes
**zero** bad observations. After the drop the pair is not held at
`h_open(E+1)`, so it is not drawable in `E+1` or after and receives no
further observations (`SO-D5`'s inversion: absent row ⇒ non-observation ⇒
the denominator shrinks). Its window cannot grow:
`failure_window_slashable` (`failure_window.rs:361–385`) needs a miss at
the head **and** `m = 11` misses within `n ≤ 13` (`:150–155`). A pair
with ten misses in twelve observations before the drop stays there for
good — the drop cannot land a slash, and there is no "next epoch" in
which it could. *SUPERSEDED:
"accumulates exactly one bad observation"; "slashable next epoch
regardless" — both written against the pre-(3.3) worst case, and the
second was wrong even there (an eleventh miss at the head slashes at
that settlement, and a non-drawable pair never gets one).*

The obvious gaming case is already closed by landed code. Hold at open,
drop early, collect anyway does not pay: `db_lmdb.cpp:5377–5383` forfeits
the drop epoch's pending acceptances, and serve-credit acceptance goes
through `holds_shard_of`. Earnings for `E` are zero, not reduced.

**(3.2) The enumerator is a pure function over append-only history.**
Home: `shekyl-chain-rules`. No store handle (DRS-D12). Reads arrive as a
`ChainView` projection. Output is a value type.

```text
DrawableSet::at_epoch_open(view, E) -> Vec<DrawablePair>
```

No snapshot table. Runs once per epoch into `EpochAssignmentCache`, which
was already designed as derived-never-persisted (`SO-D8e`) and is therefore
untouched by the redb port. The named type is STAGED in this plan; the
body lands with Slice C (not authorized).

**(3.3) The drop filter lives at settlement, not at draw.**

- **Settlement writer** — for each drawn pair, evaluate `holds_shard_of`
  at the fire height. Not held ⇒ write no row. Absent ⇒ non-observation,
  which is exactly `SO-D5`'s semantics and exactly right: the pair was
  not observable.
- **Witness** — the identical predicate at the identical height, used to
  skip the fetch. Saves 3.33 MB per dropped pair (`ARCHIVAL_SHARD_FETCH.md:180`),
  needs no coordination because both sides evaluate the same function.

#### The finding that forced this shape

`archival_bond_holds_shard_of` documents its drop semantics at
`db_lmdb.cpp:5377–5383`: a voluntarily dropped shard "keeps no interval
(grace-tail, P2B-7 Pin 2 — ratified: no drop sub-state, no
`bond_event_log` row), so it answers not-held for every height."

The point query is therefore **retroactively falsified by a later drop**.
Build the drawable set by enumerating at tip and filtering with
`holds_shard_of(h_open(E))` and a node computing at `h_open + 100` gets a
different `D` than one computing at `h_open + 5000`, if a drop landed
between. `D` changes ⇒ `total` changes ⇒ every draw index changes.

This retires a superficially attractive alternative: defining drawability
as "held at `h_open` and still held now." It contradicts the ruled
definition at `ARCHIVAL_CHALLENGE_MECHANISM.md:270` and it is precisely
the construction that makes `D` time-varying. Recorded so the round does
not re-derive it.

The mechanism doc's stability argument at `:195–197` is about **reorg**
stability. This exposure is **drop** stability. Different axis; the
existing argument does not cover it.

#### Construction

**Sources.** All are append-only pre-image journals, written at connect,
read at pop, and not touched by `prune_archival_epochs_before` (verified
`db_lmdb.cpp:7760–7795`: that function deletes serve-credit, settlement,
`r_market`, sigma-work, budget, budget-accrual and attestation-witness
rows only):

- `archival_bond_holdings_update_log` — stores `pre_shard_ids`,
  `pre_shard_add_epochs`, `pre_bonded_total`, keyed `(block_height, seq)`
  (`db_lmdb.cpp:6834–6847`).
- `archival_bond_unbond_log` — required: on release the record survives
  at tip but `held_shard_ids` is cleared (`db_lmdb.cpp:6626–6627`), so
  tip state no longer says what it held. `bad_intervals` on the record
  gives an independent cross-check of exit epochs.
- the reinstate log.
- the slash log — note `archival_slash_removed_holding_after`
  (`db_lmdb.cpp:5253–5259`) reconstructs slash removals but **only**
  slash removals; it is not a general holdings history.

**Algorithm.** Enumerate bond records at tip → expand the
`is_complete_tree()` arm over the shard registry → walk the journals
backward from tip to `h_open(E)` applying pre-images to recover each
record's holdings as they stood → filter → emit in canonical order.

**Pins** (each is a way to get this silently wrong):

1. **Exclude bonds with `E_join ≥ E`.** A bond posted after `h_open(E)`
   is present at tip and was not drawable. The record carries `E_join`;
   the rule is the existing `E_first = E_join + 1`.
2. **`CompleteTree` expands over the shard registry as of `h_open(E)`,
   not tip.** `k` grows during an epoch, so a tip-based expansion makes
   foundation records contribute a time-varying pair count — the same
   instability on a different axis.
3. **Canonical order sorts `shard_id` numerically.** Not wire bytes.
   The crate-level comment names this as a second-implementation hazard
   and `ChallengeUrn::new` rejects violations, so it fails loudly — but
   get it right rather than relying on the reject.
4. **Below the retention watermark, refuse — do not degrade.** The
   backward walk will otherwise stop early and silently return something
   nearer tip holdings than `h_open` holdings: a wrong `D` with no
   error.    Model the refusal on `StoreCannot::PopBelowFloor`
   (`shekyl-chain-store` `store/error.rs:295`) — a loud capability
   limit, not a defect and not a verdict — **at the enumerator during
   ordinary operation.** At the slash pass the same refusal means the
   node cannot settle an epoch it is obligated to settle, and skipping
   is forbidden, so it escalates to the `SO-D8d` Fault (§6.3 item 3,
   §6.4). Same refusal, two dispositions; the call site distinguishes
   them.
5. **`SO-D1`'s absent-row theorem restates** from *absent ⇒ never
   issued* to *absent ⇒ no live obligation in `E`*, covering both
   never-issued and issued-then-exited. Landed in
   `ARCHIVAL_SETTLEMENT_WRITER.md` in the same edit.

**Cost.** `O(holdings changes since h_open)` plus the tip enumeration.
Bond posts and holdings updates are rare relative to blocks. Benchmark
against a synthetic churn rate; do not assume it is under the 1.09 s
full-urn replay.

#### Gaps closed by reading — not reopened

**Empty `D` at genesis.** `ChallengeUrn::new` (`challenge_assignment.rs:147–176`)
rejects only zero `λ` and zero epoch-blocks. An empty pair vector gives
`d32 = 0`, `total = 0`, and the Bresenham schedule places zero draws in
every block, so `draw_below`'s `assert!(n > 0)` is never reached. Empty
assignments for the epoch, no error. `D = 1` works via the `n == 1`
wave-tail, which forces index 0 while still evaluating the stream so a
second implementation matches byte-for-byte.

**Slashed-away pairs.** Covered by §7.4 (3.3)'s filter, via a different
journal path than a drop:

- A slash **preserves the interval** — `holds_shard_of` answers held
  before the slash, not-held after. So a pair slashed mid-`E` held at
  `h_open(E)` and stays in `D` for `E`, correctly. At `h_open(E+1)` it
  is gone.
- Within `E` after the slash, the settlement filter returns not-held
  and writes no row. Same outcome as a drop, no special case needed —
  do not add one.
- `has_archival_slash_applied` is pair-epoch keyed, one slash per
  `(P, s, E)` (`db_lmdb.cpp:5687–5696`), so a second slash in an epoch
  is already impossible independently of this.

The **asymmetry is correct** and is stated so it is not "fixed": the
drop erases retroactively (not-held at every height, epoch's credits
forfeited — a forfeit); the slash preserves history (held until the
slash — a finding). They converge at the filter, so the filter needs
one predicate, not two.

### 7.5 Q8 RULED 2026-09-16 — the witness key

Under R-B the filer is not positional in `h`. Consensus needs a key the
producer of `h` can sign with, whose public half is committed in `h`.

**Ruled: a dedicated non-output hybrid key.** The coinbase output's own
per-output hybrid key is **ruled out** by `PL-D3`'s premise (§2.2): that
key is published once, at spend; a witness reveal is a second
publication labelled *"producer of `h`"*. A dedicated never-spent extra
coinbase output works and is refused: it costs a leaf, a 64-B `0x07`
entry, and a KEM ciphertext per block, all scan-verified for a key that
never spends.

#### Derivation

IKM is the coinbase **output 0** `combined_ss` (the miner path is
per-output KEM — `cryptonote_tx_utils.cpp:205–211`). Extract under the
existing salt `HKDF_SALT_OUTPUT_DERIVE = "shekyl-output-derive-v1"`
(`derivation.rs:94`). Expand under new labels `LABEL_WITNESS_PQC` /
`LABEL_WITNESS_ED25519`. **Info is the label alone — no `output_index`.**
`derive_output_secrets` concatenates `idx_le64` onto every expand
(`derivation.rs:171–183`); the witness key is per-block, not per-output,
and a sentinel index would be a colliding-looking child of the output
scheme. Same Extract, distinct Expand, registry mechanism 2 (review
duty, count-pin does not cover it). The resulting hybrid key has no
leaf, no `h_pqc`, and no spend path — F5/`PL-D3` cannot reach it.

#### `combined_ss` is not on the FFI result

`shekyl_construct_output` is the coinbase construction site. Its result
`ShekylOutputData` (`shekyl_ffi.h:644–661`) carries `output_key`,
commitments, KEM ciphertexts, `pqc_public_key`, `pqc_leaf`, and
`y`/`z`/`k_amount`. It does **not** carry `combined_ss`. After
`shekyl_output_data_free` the secret is gone. The daemon constructing
the miner tx holds `txkey.sec` only for that call and does not hold the
miner's ML-KEM secret, so it cannot recover `combined_ss` later by
decap.

Derive the witness keypair **inside Rust** at miner-tx construction —
the same call that already has output 0's `combined_ss`. Return only the
32-byte commitment for `tx_extra`. Stash the seed in the Rust-owned
`W₂` ring (Q10). **Do not punch `combined_ss` across the FFI** (rule 36).
Do not hang a per-block field on the per-output `ShekylOutputData`
struct; the miner-tx constructor (Q15: Rust) is the home.

#### Commitment home is `0x0C` — extending `0x0B` is SUPERSEDED

The check this ruling was waiting on: whether `0x0B`'s blob has a
length or version prefix that makes extension clean. It does not.

- `tx_extra_archival_attestation::blob` is the concatenation of `k`
  canonical `ARCHIVAL_ATTESTATION_HEADER_BYTES`-byte records
  (`tx_extra.h:213–228`). Header = 49 B (`p_id‖s‖E‖kind`,
  `attestation_wire.rs:29`). **No version prefix. No length prefix.**
- Admission requires `headers.len().is_multiple_of(ATTESTATION_HEADER_LEN)`
  and `k ≤ 256` (`shekyl-ffi/src/archival_ffi/attestation.rs:204–207`).
  Appending 32 B of `H(witness_pk)` is `32 ≢ 0 (mod 49)` and is refused.
  Prefixing 32 B (or a version byte) is a format change to a
  genesis-frozen field (rule 42).
- Empty set = **absent tag**, not an empty blob
  (`cryptonote_format_utils.cpp:685–701`: parse success with no tag is
  `true` and `blob.clear()`). A witness commitment is per issuing block
  and must exist even when the block includes zero records. Forcing
  `0x0B` always-present to carry it would change the empty-set encoding.
- `0x0B` names records **included in** this block. The witness key names
  this block **as issuer `h`**. Those are different concerns; stuffing
  the second into the first splits one wire across two meanings.

`0x0C` is the next free live tag (`tx_extra.h:38–52`: `0x00`–`0x0B`
allocated except retired `0x03`/`0xDE`; `0x0C` unused). Opaque
`std::string` blob, same serializer shape as `0x07`/`0x0B`. Content
rule (exactly one entry, exactly 32 B, coinbase only, **mandatory-present**)
is Q13; presence is already decided (§7.5 P1). 34 B permanent in `h`'s
coinbase prefix (tag + one-byte varint + 32 B); the 1,996-byte key
(`PQC_HYBRID_SINGLE_KEY_LEN`) is revealed later in the pruned side of
the record and hash-checked. Verify is `HybridPublicKey` /
`HybridEd25519MlDsa` — the same path P's emission countersignature
already uses (`emission_verify.rs:743–763`). No new primitive.

**SUPERSEDED:** "extend `0x0B` rather than mint `0x0C`." The original
proposal's `0x0C` stands. Tag space is a genesis-frozen resource; this
is a spend of it that the format of `0x0B` forces.

#### Pins Q13 and Q10 inherit (attached 2026-09-16; Q13 RULED same day, §7.8)

**(P1) Mandatory-present, not optional-absent — Q13 content, decided
against commitment 2.** If `0x0C` appears only when the producer intends
to witness, its presence is a per-block declaration of who witnesses.
Correlate that with coinbase analysis and the tag is a per-pool
behavioural fingerprint — and β, the persistent non-witnessing fraction
that [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md)
§7 item 7 (`:1150–1155`) requires be treated as **common-mode**, never as
i.i.d. noise the window launders, becomes directly observable and
attributable. Always-present costs tag + varint length + 32-B commitment
= 34 B/block (`tx_extra.rs:169–173`: `write_blob` is `[tag] ‖ varint(len)
‖ blob`; `len = 32` is a one-byte varint), ≈ 9 MB/year permanent at
120 s/block (`cryptonote_config.h:50`), and carries **no signal**. That
is the right trade: privacy is the product (`00-mission` commitment 2);
byte count does not enter. Q13 RULED (§7.8): the CEN row is one
predicate over one field, five fixtures; it does not re-open
optionality. Length is `WITNESS_COMMITMENT_BYTES`, not a literal.

**(P2) Per-block uniqueness of `combined_ss` is a derivation requirement,
not a KEM inheritance.** Dropping `output_index` from the witness info is
correct for a per-block key, which means uniqueness comes entirely from
output 0's `combined_ss` differing block to block. `derive_kem_seed`
(`derivation.rs:239–261`) is deterministic over `(tx_key, recipient
x25519_pk ‖ ml_kem_ek, output_index)`. Today's miner path happens to
call `keypair::generate` (`cryptonote_tx_utils.cpp:131`), so a fresh
`tx_key` currently implies a fresh `combined_ss` — that is an accident
of the constructor, not a property of the KEM. A miner whose coinbase
encapsulation is deterministic over a fixed payout address (reused
`tx_key`, or a later constructor that drops `tx_key` from the IKM)
produces the same `combined_ss` for two blocks, the same witness key,
and the 32-B `0x0C` blobs match: a cross-block miner identifier, which
is exactly what the dedicated key exists to avoid. **Pin:** the miner-tx
constructor must use a fresh `tx_key` per block; Slice C ships a fixture
that two constructions to the same payout address with independently
generated `tx_key`s yield distinct `0x0C` commitments, and that the same
`(combined_ss)` pair yields the same witness key. The fixture fails if
uniqueness is ever inherited from "the KEM is random" rather than from
the constructor's freshness.

**Q10 inherits the ring size from always-present — and RULED 2026-09-16
(§7.7) accept loss against it.** Every block carries a witness key, so
the `W₂` ring *capacity* is `CHALLENGE_RESPONSE_BLOCKS` (= 500,
`constants.rs:147, :202`) seeds keyed by height, not one. Steady-state
depth tracks fill-to-inclusion, not the deadline. A restart that loses
in-flight seeds surfaces as β (non-observation of those heights'
draws), not as an error — same disposition the wargame already named;
the cardinality is the inherited fact. Persist-encrypted is **REJECTED**.

#### What Q8 does not pin — SUPERSEDED 2026-09-16 (Q12 RULED)

The 32-B commitment's **shape** is Q12 RULED (§7.9): a bare
`cSHAKE256` of the canonical key bytes under
`shekyl/archival-witness-key-v1`. The tag is no longer blocked on F5.
Enumeration (`pre_shard_ids`) and join (F5, Q12) are different
attacks. Q12's reveal publishes `pk`, so hiding is theater; the join
identifies `h`'s coinbase, which was already public. *SUPERSEDED:
"sequenced behind F5 / `PL-D3`"; "do not land the tag ahead of that
inheritance."*

### 7.6 Q9 RULED 2026-09-16 — set-commitment batching, carrier fail-whole, resubmission within `W₂`; amended same day

The question was whether the witness files ~97 records for issuing
block `h` as one transaction sharing one pk reveal and one signature, or
as separate records each carrying its own witness material.

**Form — as amended 2026-09-16.** One pk reveal and one signature per
carrier, over a **set commitment** of the carrier's records (§7.6.1). The
carrier is **fail-whole**: any member failing its own record predicate
refuses the carrier (`InvalidBlock`, naming member `i`), and the witness
refiles without it inside `W₂`. No per-record inclusion paths. Unbatched
(5,381 B of witness material per record) remains rejected.

**SUPERSEDED same day: Merkle-root batching with per-record inclusion
paths.** It was chosen so that "a corrupt record can be excluded and the
rest verify." That premise was false under the carrier contract
(§7.6.2): all members are vins of one transaction, and one failing vin
refuses the transaction whether the signature is over a root or a
concatenation — so the paths bought isolation at the *signature* while
admission stayed fail-whole regardless. Once that is seen, the paths are
22 KB/block for nothing: resubmission — which the reorg finding (§7.2)
makes mandatory machinery anyway, since orphaned records are
re-submittable verbatim — already provides the isolation the paths were
bought for. The malicious-witness case does not separate the two forms
either: a witness that wants to deny 97 credits simply does not witness,
at zero cost, under both. The original objection to fail-whole — one
corrupt record costs 96 honest archivers their credit — priced a
**loss**; with `W₂ = 500` it is a **round-trip**.

**Two consequences ruled with it, unchanged.** The dedup key stays
`(P, s, E, h)` per record — a batch is a carrier, not a unit of credit.
Admission of a record proves membership in a set that witness authored,
not that the set was complete; a witness filing a subset is
indistinguishable from one that never drew those pairs, which it can
already achieve by not witnessing. Subset filing grants no power it
lacks today.

**Why batching is worth doing (restated).** Not penalty avoidance.
`effective_median` is a 100k-block long-term median and a 100-block
short-term median clamped to `[Mlw, S·Mlw]` (`block_weight.rs:36–39`);
the fee ladder prices against the long-term effective median (`:10–17`).
300,000 is `get_min_block_weight` (`cryptonote_basic_impl.cpp:81–85` =
`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5` at
`cryptonote_config.h:58`), a floor, not a ceiling. Sustained archival
load raises the median and the steady state is penalty-free. At
maturity the archival traffic *sets* that median, so 850 KB versus
335 KB is a 2.5× difference in the baseline every other participant's
fees price against, and in relayed volume — roughly 223 GB/year against
88 GB/year at 120 s/block, mostly prunable. Permanent bytes are
unchanged at ~12 KB/block ≈ 3.2 GB/year either way. Both byte figures
are provisional on `D ≈ 324k`, a maturity assumption from the proposal
rather than a measured constant.

**There is no fee, and there cannot be one.**
`txin_archival_serve_credit_response` is a `txin_v` variant
(`cryptonote_basic.h:269,315`). The coinbase's `vin` must be exactly one
`txin_gen` (`blockchain.cpp:1394–1395`), so records ride ordinary
transactions — never the coinbase. `archival_tx_kind::serve_credit_only`
is handled at `blockchain.cpp:3484–3488` as non-spending archival vins
(empty body: no `txin_to_key`, no value inputs). Semantic gate:
`txnFee != 0` is a refusal (`tx_verification_utils.cpp:117–119`).
**SUPERSEDED:** item 8(a) / F3's surviving half, "who pays the fee."
The tx-pool class (item 8(c)) is `serve_credit_only`.

**Prunable bytes count toward `block_weight` — confirmed at the weight
path, not inferred from a missing carve-out.** Admission (unpruned):
`get_transaction_weight(tx, blob_size)` returns `blob_size` plus the
Bp+ clawback (`cryptonote_format_utils.cpp:323–334`); it refuses pruned
txs. Serve-credit is `CTTypeFcmpPlusPlusPqc` (`is_ct_bulletproof_plus`
true, `ct_types.cpp:205–213`) with empty `bulletproofs_plus`
(`tx_verification_utils.cpp:121`), so clawback is 0 and weight is the
full-blob size. The blob is the parse of the entire wire
(`cryptonote_format_utils.cpp:201–208` sets `blob_size` from
`tx_blob.size()`), and RF-D1 put the pass records in the prunable
region (`transaction.rs:1850–1873`: serve-credit now *carries* a
prunable region). After prune:
`get_pruned_transaction_weight` serializes the pruned tx then **adds**
`ARCHIVAL_SERVE_CREDIT_PRUNED_RECORD_BYTES * count_serve_credit_inputs`
(`cryptonote_format_utils.cpp:374–379`; constant 5,107 at
`cryptonote_config.h:432–433`) so a pruned node reconstructs the same
weight. Rust `Transaction::weight` is `serialized_len() +
bp_plus_clawback()` (`transaction.rs:1457–1466`); `serialized_len` is
`write` into a counting sink, and `write` includes prunable. There is
no archival carve-out on this path; the reconstruction *is* the
inclusion.

**Inherited per-tx cap, not a Q9 reopening.** Rule 4 of
`ver_non_input_consensus` applies `get_transaction_weight_limit` =
`get_min_block_weight / 2 − 600` = 149,400
(`tx_verification_utils.cpp:80–86, :203–207`;
`CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE` at `cryptonote_config.h:60`;
Rust `TX_WEIGHT_LIMIT` at `transaction.rs:144–149`) with no archival
carve-out. A carrier above it is `m_too_big`. At the maturity figures a
single-tx ~336 KB carrier of 97 records does not fit; the witness
splits into as many carriers as the limit requires. Split is subset
filing — already granted. Raising the cap for archival is the same
fee-and-weight round as a prunable-weight discount, not Q9.

**Split arithmetic — re-derived 2026-09-16 for the amended form.** No
path bytes, so a carrier holds
`⌊(149,400 − 5,381) / 3,411⌋ = ⌊144,019 / 3,411⌋ = 42` records. 97
draws split **42 / 42 / 13**. Witness material `3 × 5,381 = 16,143 B`
instead of 5,381, +10.8 KB/block. Total
`97 × 3,411 + 16,143 = 347,010 B ≈ 347 KB/block` rather than 336 KB,
still ~2.4× better than 850 KB. Amortization **42:1**, not 97:1.
Raising the cap to admit a single 97-record carrier is worth
~11 KB/block ≈ 2.8 GB/year (262,980 blocks/year × 10,762 B) — carry to
the fee-and-weight round; it is not a Q9 reopen. *SUPERSEDED: 39 / 39 /
19 at depth 6 with a 192 B path; ≈ 365 KB/block; 39:1.*

**Inter-carrier blast radius.** Three transactions are three
independent inclusion decisions. A miner taking 2 of 3 costs **42**
archivers that inclusion, and a carrier refused for one bad member costs
its **41** honest members one round-trip. `W₂ = 500` is therefore
resubmission headroom for an unincluded or refused carrier, not only
fetch time; shrinking `W₂` must price that. *SUPERSEDED: "the blast
radius Q9 refused inside a batch reappears between batches" — Q9 no
longer refuses it inside the batch; it prices it as a round-trip in
both places.*

**Partition leaks nothing (non-finding).** Which records land in which
carrier is witness-chosen and public. The set at `h` is derivable from
`block_hash(h−1)` by anyone. Assignment is already public; the split
does not add a leak.

**The residual, held.** Nobody pays for these bytes anywhere in the
pipeline: the witness is unpaid by ruling, and the record transaction
is structurally fee-less. Inclusion rests on miners voluntarily
carrying zero-fee data. A block below the median takes no penalty for
extra weight, and `λ·D/SEB` grows smoothly enough for the median to
track it, but the marginal calculation for a miner whose block is at
the median is to omit. Whether that bites is a dynamics question for
the economics sim. The lever if inclusion turns out to be
under-incentivised is to weight prunable archival bytes differently —
the same decision as the weight-path fact above, approached from the
other side. Both belong to a fee-and-weight round, not Q9. Cap-raise
value (~11 KB/block) sits on the same round.

**FOLLOWUPS row added 2026-09-16** (rule 22: a deferral names its
carrier): *Serve-credit inclusion incentive and archival weight pricing
(the fee-and-weight round)* — unpaid inclusion, prunable-weight
discount, cap-raise; falsified by the economics sim's inclusion rate at
median-bound blocks.

#### 7.6.1 The set commitment — PROPOSED 2026-09-16, string settled; vectors re-cut same day

**Review finding (valid).** The shape ruled above does not fix bytes,
and rule 30 requires every hash to sit under an explicit, versioned
domain; rule 05 wants the spec before Slice C writes the bytes. With
inclusion paths gone the construction collapses to one hash.

**The string is settled, not open.** The tree runs two consistent
families with a clean split — `shekyl/<domain>-v<n>` for cSHAKE
customization strings (`shekyl/archival-serve-credit-response-v1`,
`shekyl/archival-attestation-root-v1`,
`shekyl/archival-challenge-assignment-v1`; a `-v1`/`-v2` pair on
`archival-serve-challenge-leaf` and `archival-attestation-scheme` shows
versioning is exercised) and `shekyl-<purpose>-v1` for HKDF labels.
`shekyl/archival-serve-credit-batch-v1` fits the first exactly and sits
in the existing `serve-credit-*` cluster. The row lands in
`docs/design/CRYPTO_DOMAIN_REGISTRY.tsv` — the single source
(`CRYPTOGRAPHIC_INVENTORY.md:100` defers to it) that
`scripts/ci/domain_registry_gate.sh` holds against the workspace — with
the constant at Slice C; the gate is what forces the row when the
constant lands, so none is minted here.

Proposed, not ruled:

- **Commitment.** `cSHAKE256_32(frame(record_1) ‖ … ‖ frame(record_n))`
  under `shekyl/archival-serve-credit-batch-v1`, where each `record_i`
  is the member's full serialization (kept vin ‖ pruned pass record) in
  **vin order** — the order the witness signed — and
  `frame(r) = varint(len(r)) ‖ r`.
- **Framing is the whole anti-ambiguity mechanism.** Without the length
  prefix, two distinct member sets can concatenate to one byte string
  and share a commitment. It therefore carries its own vector (below);
  a rule whose violation no check detects is not a rule.
- **`n ≥ 1` is a structural check on the carrier**, named in §7.6.2's
  list — cSHAKE over the empty string is well-defined, so the
  construction does not refuse an empty carrier by itself, and the
  zero-member carrier is the exact case (A) was rejected for. `n = 1`
  is the same construction; no special case.
- **What the signature binds, and through what.** The witness signature
  is a bare signature over the 32-byte commitment. It is bound to the
  issuing block **through the records**, not directly: every member
  carries `h`, and the verifier checks `hash(witness_pk)` against
  `h`'s `0x0C` (§7.9). Two consequences: (i) third-party relay of a
  witness's carrier is possible and harmless — useful for resubmission,
  since anyone holding the carrier can refile it; (ii) Q12's reopener
  ("`h` removed in order to conceal the issuing block", §7.9) would
  unbind this signature as well, so the two rows cross-reference.
- **Enforced only where the data exists.** The commitment spans the
  pruned region, so a pruned node cannot recompute it and cannot
  evaluate the witness signature at all — it identifies the record and
  cannot re-verify (`ARCHIVAL_RESPONSE_FORMAT.md:515`; the pruned-side
  partition is `CR-D2`, RF row 1), exactly as it accepts `P`'s ML-DSA
  leg. §7.6.2's "any failing member refuses the carrier" is universal
  among unpruned validators and does not reach a pruned node, which
  accepts the carrier on the chain it follows.
- **KAT — re-cut.** With one flat hash the structural cases are `n = 1`
  and `n > 1`; a 3-record vector was there for the odd tree level and
  now exercises nothing. Vectors: (1) `n = 1`; (2) `n = 2`; (3) a
  **collision pair** — two distinct member sets whose *unframed*
  concatenations are byte-identical, pinned to distinct commitments;
  (4) a **short-record** vector crossing the 1-byte/2-byte varint
  boundary at 128 B, because real records are ~3,411 B and never cross
  it in production, so the encoding would otherwise be untested where an
  implementation is most likely to differ. *SUPERSEDED: the 3-record
  vector.*

Falsifier: the KAT — vector (3) goes red if framing is dropped and
nothing else in the suite does. *SUPERSEDED (same day): the Merkle
construction — leaf/node labels, odd-level rule, path direction from the
leaf index. None of it is needed once no member is verified without the
rest.*

#### 7.6.2 Carrier semantics — RULED 2026-09-16: (B), carrier fail-whole + resubmission

**Review finding (valid) that forced the amendment.** "Merkle inclusion
lets a bad record be excluded and the rest verify" was not what the
carrier does. All records of a batch are vins of **one** transaction; the
inherited contract refuses the whole transaction when any serve-credit
vin fails (`blockchain.cpp:3682–3691`, `return false` on input `i`), and
a `shekyl-chain-rules` row returns `InvalidBlock` for the candidate. Two
branches were recorded; **(B) is ruled.**

- **(A) Per-vin admission — REJECTED.** A valid carrier whose failing
  members are silently not credited. A new consensus semantics — *a
  valid block may carry serve-credit vins that yield no credit* — and a
  **free-weight channel**: the witness is the producer of `h` and can
  author junk members under a commitment it signs; with no fee, junk
  carriers consume block weight for nothing, and closing that needs yet
  another rule. Reopen only if a fee or weight price for serve-credit
  bytes lands (the fee-and-weight round), which would remove the
  free-weight ground.
- **(B) Carrier fail-whole + resubmission — RULED.** Structural checks
  on the carrier: kind `serve_credit_only`, fee 0, weight under the cap,
  pruned-record count equals vin count, **`n ≥ 1`** (the empty carrier is
  refused here, not left to the construction — §7.6.1), witness
  signature over the set commitment against `h`'s `0x0C`. Then any
  failing member refuses the carrier (`InvalidBlock`, naming member `i`'s
  predicate, as today) — among validators that hold the pruned region;
  a pruned node cannot evaluate it (§7.6.1). The honest members are refiled in another carrier within
  `W₂`. Isolation is by resubmission, not by admission. The witness's
  incentive to pre-verify is intact (its carrier fails otherwise), and
  its seed is still in the ring (Q10 evicts on inclusion, and a refused
  carrier was not included), so re-signing is possible. Adds no
  consensus semantics, opens no free-weight channel, and removes the
  path rule and 22 KB/block.

Neither branch touches dedup (`(P, s, E, h)` per record) or the
kept-wire ceiling. Fixture 13 is written for (B) (§8).

**SUPERSEDED** in this section: Merkle-root batching with inclusion
paths (the ruled form, same day); "fail-whole refused" as a statement
about the carrier (it was only ever true of the signature, and the
signature is now over a set commitment, which is fail-whole too);
"Merkle inclusion lets a bad record be excluded and the rest verify";
"against a 300 KB penalty-free zone"; "prunable bytes still count toward
block weight" as an unread claim (now confirmed); "who pays the fee";
"a single-tx ~357 KB Merkle-batch" as the maturity headline; 39 / 39 /
19; ≈ 365 KB/block; 39:1.

### 7.7 Q10 RULED 2026-09-16 — accept loss

The question was what happens to the witness-seed ring across a daemon
restart: persist it encrypted, or accept the loss.

**Form.** Accept loss. Memory-only ring, Rust-owned, `ZeroizeOnDrop`
(rules 35/36). Persist-encrypted is **REJECTED**. The ring holds the
32-B derived seed per height (`keygen_from_seed` takes `[u8; 32]`,
`derivation.rs:36–38`), not the expanded hybrid secret
(`ML_DSA_65_SECRET_KEY_LENGTH` + Ed25519 ≈ 4 KB,
`signature.rs:114`) and not `combined_ss` (64 B, never on
`ShekylOutputData`, `shekyl_ffi.h:644–661`). Size is not the question;
posture is.

**Why persist is refused.** It would make the daemon a secret-holder
at rest for the first time. Today `shekyl_construct_output` generates
`combined_ss` transiently inside Rust and frees it —
`ShekylOutputData` returns public material plus `pqc_leaf` and
`y`/`z`/`k_amount`; after `shekyl_output_data_free` the secret is
gone. A persisted ring is secret material in the daemon data
directory. Rule 36 §3 has an encrypted-envelope precedent
(ChaCha20-Poly1305, AAD-bound) — it is a *wallet* precedent, and a
wallet has a passphrase. A daemon has no operator secret to key an
envelope with, so "persist encrypted" resolves to a key file beside
the data, which protects against nothing an attacker with disk access
cannot already defeat.

**Why the accept-loss cost is not "500 live seeds."** A seed is needed
only until its batch is *included*. `W₂` is the deadline, not the
expected latency. Filing promptly (the operational lever) plus
eviction on inclusion makes steady-state ring depth track real
latency — tens, not hundreds — even though Q9's three-way split and
partial inclusion stretch the tail via resubmission. Restart then
drops whatever has not been included yet, not 16.7 hours of
obligations.

**Four operational pins, ruled with it.**

1. **Memory-only, Rust-owned, `ZeroizeOnDrop`.** No new at-rest
   surface, no key management, no operational burden on node
   operators.
2. **File promptly rather than lazily.** `W₂` is headroom for
   resubmission and slow fetches, not a schedule.
3. **Evict on inclusion.** A seed whose batch is confirmed is dead;
   drop it. Ring depth then tracks real latency instead of `W₂`.
4. **Make the loss observable without inventing a count the process
   no longer has.** Orderly shutdown: log the exact remaining ring
   depth, then drop. Unclean restart (crash / OOM): the ring is gone;
   log that this node's in-flight witness obligations are lost and
   the count is **unknown**. Do **not** persist a cardinality beside
   the datadir — that is a new at-rest surface for a log line, and a
   crash still loses it unless it is fsynced on every fill, which is
   persistence by another name (refused with this ruling). A generic
   potential-loss warning on every unclean start is the signal. Not an
   error — it is a capability limit — but an operator who restarts
   hourly should be able to see that they are a poor witness.

**β is common-mode, and restart-correlated loss is the worst shape.**
`ARCHIVAL_CHALLENGE_MECHANISM.md` §7 item 7 (`:1150–1155`) requires
the persistent non-witnessing fraction β be treated as **common-mode
across epochs, never as i.i.d. noise the window launders**. The
`λ_eff` tripwire guards exactly this. Upgrade rollouts, crash loops,
and OOM kills hit many nodes in the same window. Loss is silent
unless pin 4 fires.

**Named fallback, REJECTED-for-now (rule 21).** If β turns out to be
restart-dominated, the fix is **not persistence**. It is
**re-derivability**: make the coinbase `tx_key` deterministic from a
long-lived node secret and `h`, so `combined_ss` and everything
downstream recompute after restart with nothing retained. That
trades 500 ephemeral secrets for one persistent one — a strictly
better shape for an encrypted-at-rest story if one is ever needed.
It preserves Q8 P2 (independent `h` values still give distinct
commitments) and the `tx_key` stays unpredictable to outsiders, so
no coinbase privacy is lost. It changes coinbase construction, which
is consensus-adjacent, so it is held as the named fix rather than
built now.

**Reopening criterion (falsify, do not wait).** Accept-loss stands if
inclusion typically lands within a few blocks. It reopens to
re-derivability — **not** to persist — if a sim of restart-to-restart
intervals against fill-to-inclusion latency shows partial inclusion
routinely dragging batches toward `W₂`, because then the ring really
is deep and restarts really do cost a large slice. Falsify by running
that sim; an unread "blocked until measured" is the shape rule 22
forbids. Persist stays refused on independent grounds (no operator
secret) even if the sim reopens the fallback.

**SUPERSEDED** in this section: persist-encrypted as the restart
policy; "500 live seeds" as the expected ring depth (that is the
capacity, not the steady state).

### 7.8 Q13 RULED 2026-09-16 — the `0x0C` content rule

**One `CEN-` row in `shekyl-chain-rules` (id at Slice C), one predicate
over one field, five fixtures. Domain: from genesis, unconditionally.
Surface-free — a pure function of the block's coinbase `tx_extra`, no
store handle — landable as an E6 increment with deadline and SO-D9,
well ahead of S-ARCH.**

The four clauses Q8 named (exactly one entry, length
`WITNESS_COMMITMENT_BYTES`, coinbase only, **present**) are one
predicate. A verifier at `h_incl` reading `h`'s commitment has no
guarantee of what it reads if `0x0C` can be absent, duplicated, or
mis-sized. Everything Q8 bought rests on this row.

**One row, not four.** The census's *"new callee that can reject ⇒ new
row"* (`CONSENSUS_RULE_CENSUS.md:1388–1389`) names a callee on a
re-walk, not a clause of one predicate. Four IDs for one parser would
mint four grep surfaces for one function. Each independent refusal is a
fixture of the same row.

**Predicate co-located with `0x0B`'s concern; site is a chain-rules
row (Q15).** Both are coinbase `tx_extra` fields; putting `0x0C` in a
different pass invites the two to drift. Today's 0x0B read
(`blockchain.cpp:5306`) and the FFI p_ids bounds (`:5315–5317`) are
records-was of the LMDB path — Q15: C++ never learns this gate. The
CEN row lands at Slice C. Non-coinbase `0x0C` is a tx-admission
refusal, same row: today an unknown tag is unparseable
(`tx_extra.rs:175–176`); once `0x0C` is in the grammar, a known tag with
no consumer is a free 32-B covert channel in every user transaction.

**Dedicated parser `parse_archival_witness_commitment_from_extra`.** It
must not follow `parse_archival_attestation_from_extra`. That function
documents (`cryptonote_format_utils.cpp:687–692`) that a successful
parse with no attestation tag returns **true with an empty blob** — the
committed empty set — distinguished from parse failure, because
collapsing the two would let a malformed coinbase extra pass for the
empty attestation set at admission while the settlement scan later
reads the same bytes. That is correct for `0x0B`, where zero records is
a legitimate state. It is exactly wrong for `0x0C`, where absent must
reject. Copying the `0x0B` parser — the natural thing — produces
silently wrong semantics with a well-argued comment sitting above it.
The divergence belongs in a comment at the `0x0C` site as carefully
argued as the one it is deliberately not copying.

**"Exactly one" is a count, not first-wins.**
`find_tx_extra_field_by_type` (`cryptonote_format_utils.h:70–77`) takes
`index` defaulting to 0: `!index--` skips until the index hits 0, then
returns. It is first-wins, not reject-on-duplicate. The `0x0B` path
calls it at `cryptonote_format_utils.cpp:699` with the default. A
second `0x0C` is silently ignored unless something counts. The parser
counts; first-wins is the red edit.

**Length is `WITNESS_COMMITMENT_BYTES`, not a literal 32.** Q12 RULED
(§7.9): the value is 32. A Q12 reopener (`h` removed in order to
conceal the issuing block, or a `PL-` ruling that forbids publishing
`pk`) revises this constant in one place — a revision to this row, not
a new row. A compactness drop of `h` that leaves it public-by-join
does not fire. Dropping exact-length for a minimum is the red edit.

**Domain: from genesis, unconditionally.** Pre-genesis there are no
prior blocks. An unstated domain would make every block before the rule
exists invalid; stating "from genesis" is required, not inferred.

**Budget (the check before ruling).** Framing is tag + one-byte varint
+ `WITNESS_COMMITMENT_BYTES` = 34 B today (`tx_extra.rs:169–173`).
Coinbase extra occupants already on the wire:

| Occupant | Bound | Source |
|---|---|---|
| nonce | `TX_EXTRA_NONCE_MAX_COUNT` = 255 | `tx_extra.h:36` |
| `0x06` KEM ciphertext | 1,120 B/output (`HYBRID_KEM_CT_BYTES`) | `tx_extra.h:157` |
| `0x07` leaf entries | 64 B/output (`PQC_LEAF_ENTRY_LEN`) | `tx_extra.h:175` |
| `0x0B` attestation | `k × 49` B, `k ≤ 256` → 12,544 B | `cryptonote_config.h:443–444` |
| pubkey | 32 B | `TX_EXTRA_TAG_PUBKEY` |

`MAX_TX_EXTRA_SIZE` = 24,576 (`cryptonote_config.h:352`) is documented
as the **non-coinbase** extra cap (`shekyl-wire`
`transaction.rs:131–132`) and is checked only on
`construct_tx_with_tx_key` (`cryptonote_tx_utils.cpp:585`).
`construct_miner_tx` does not check it. `COINBASE_BLOB_RESERVED_SIZE` =
600 (`cryptonote_config.h:60`) is a **weight reserve subtracted from
`TX_WEIGHT_LIMIT`** (`transaction.rs:141–143`), not an extra cap. The
attestation cap itself records the fact
(`cryptonote_config.h:440–442`): *"the coinbase has no other tx_extra
size check on the connect/validate path"* — `256 × 49` B is the bound
they chose for `0x0B`. KEM at 1,120 B already exceeds 600; `0x0B` at
max is ~21× the reserve. Do not price `0x0C` against 600 as if it were
a coinbase extra ceiling — that ceiling does not exist, and `0x0B`
already owns the question of how large coinbase extra may grow. 34 B
is rounding against `0x0B`'s worst case and against a typical
one-output coinbase (pubkey + KEM 1,120 + leaf 64). Mandatory presence
is a permanent 34 B/block claim (~9 MB/year, already priced at P1
against commitment 2). It does not move the 600-reserve question.

**Five fixtures, each named with the edit that makes it red:**

| Case | Expect | Red edit |
|---|---|---|
| exactly one, `WITNESS_COMMITMENT_BYTES`, coinbase | accept | — |
| tag absent from coinbase | reject | adopting `0x0B`'s empty-set convention |
| two `0x0C` fields | reject | relying on `find_tx_extra_field_by_type`'s first-wins |
| `WITNESS_COMMITMENT_BYTES ± 1` | reject | dropping the exact-length check for a minimum |
| `0x0C` in a non-coinbase tx | reject that tx | omitting the rejection and letting a known tag's tolerance swallow it |

**Does not:** mint the `CEN-` id (Slice C); re-open P1 optionality;
re-open `0x0B`; implement a parser. The tag lands with Slice C; Q12
no longer blocks it.

**SUPERSEDED:** optional-absent (already P1); copying the `0x0B`
parser; four CEN rows for four clauses; unread
"`COINBASE_BLOB_RESERVED_SIZE` is the coinbase extra ceiling"; a
literal `32` as the length clause; "land the tag ahead of Q12/F5."

### 7.9 Q12 RULED 2026-09-16 — witness commitment is a bare hash

**Bare `WITNESS_COMMITMENT_BYTES` (= 32) hash of the canonical witness
pk, `cSHAKE256` under customization `shekyl/archival-witness-key-v1`.
Ruled on its own analysis, not as an inheritance from F5.** Located by
question (2) against `PL-D3`'s reveal-once: the circuit opens `CM`
without publishing `pk`; Q12's ML-DSA verify publishes `pk`. Conclusion
unchanged. *SUPERSEDED: arguing as if F5 were still an open round
(the 2026-09-16 F5 agent brief, WITHDRAWN §1.5).* Not
`PL-D3`'s `pqc_key_scalar`. The real residual is P2 (fixture 12), not
the hash shape.

**Customization, checked against the registry before naming.**
`docs/design/CRYPTO_DOMAIN_REGISTRY.tsv` is the single census (SA-3b).
Mech 1 is cSHAKE256 customization; live archival strings are
`shekyl/<name>-vN` (`shekyl/archival-serve-credit-response-v1`,
`shekyl/pqc-leaf-record-v1`, …). The hyphen form that looked like a
second convention is a **different mechanism**: HKDF salt/info
(`shekyl-output-derive-v1`, mech 2) and the retired Blake2b DST
`shekyl-pqc-leaf` (mech 4, replaced by `shekyl/pqc-leaf-key-v1`). The
TSV header states that style inconsistency across mechanisms is
intended and permanent; aligning a live string is a KAT-remint. The
candidate does not collide with any mech-1 literal. The TSV row, the
const, and the mech-1 census pin (`domain_registry.rs` `30 → 31`) and
count-pin +1 land with Slice C — a row without a defining site fails
the gate. Do not mint the row in this docs PR.

F5's mechanism and Q12's question look identical and aren't. The
decision procedure, three questions **in this order**, is what locates
Q12 relative to `PL-D3`. F5's round already answered (2) with
reveal-once (in-circuit opening, `pk` unpublished until spend). Q12
fails (2) because ML-DSA verify publishes `pk`. A reader who starts
at (3) will propose hiding for objects where it buys nothing.
*SUPERSEDED: "is what F5's round should apply" — that round closed
two days before the 2026-09-16 brief treated it as open.*

1. **Is the preimage enumerable?** If yes, the digest is an index;
   hiding or a larger domain is required. `pre_shard_ids` fails here.
   F5 and Q12 both pass — `PQC_HYBRID_SINGLE_KEY_LEN` = 1,996
   (`cryptonote_config.h:386`). Collapsing (1) into F5's framing is
   what made a 1,996-byte preimage look radioactive.
2. **Does the reveal publish the preimage?** If yes, hiding is
   theater: `C = H(pk ‖ blind)` in the coinbase with `(pk, blind)` in
   the pruned half leaves the join intact — bytes and an opening for
   nothing. The only remedy is a protocol that **stops publishing**.
   Q12 fails here, which is why a bare hash is correct: nothing better
   is purchasable. ML-DSA verification structurally requires the key;
   putting the witness signature in zero knowledge is not an option,
   it is unavailable. F5 passes (2) only because the circuit opens
   without revealing (`PL-D3`).
3. **Does the join identify more than the reveal was entitled to
   identify?** F5 fails — membership was the entitlement, the specific
   output is what the join gives. Q12 passes — one producer of `h`,
   and identifying them *is* the predicate.

The load-bearing fact for (3) is not that `h` is a kept field. `0x0C`
sits in `h`'s miner transaction next to output 0 — co-location binds
the commitment to a public block and a public payout whether or not
the record names `h`. The kept field (`117 → ~125` B, §2.1) makes that
explicit; it is not what prevents a leak. The join identifies `h`'s
**coinbase**, not the miner as an entity: the coinbase pays a stealth
address, so "whoever received `h`'s coinbase" is the most anyone
learns, and that was already in the block. Nothing about the reveal
reaches the payout identity.

**Adjacent leaks, all closed.** Cross-block linkage of the witness
key: P2, fixture 12 — that is the real residual. Output 0's hybrid
key: sibling Expand under `LABEL_WITNESS_*` vs `LABEL_OUTPUT_PQC` /
`LABEL_OUTPUT_PQC_ED25519` (`derivation.rs:94,:115–116`). Which blocks
witnessed: records already name `h`; P1 priced always-present.

**Reopeners:**

1. **Falsify if `h` is removed in order to conceal the issuing
   block.** A compactness move that leaves `h` public-by-join (verifier
   searches `0x0C`) does not invert the analysis. Concealment would:
   the transparent commitment becomes a fig leaf, and the protocol
   would have to stop publishing `pk`. It would also **unbind the Q9
   carrier signature**, which reaches the issuing block only through
   the records' `h` (§7.6.1) — the two rows cross-reference.
2. **A blanket "all published commitments hide" is a process
   reopener, not an analysis inversion.** Pedersen-then-open-in-the-clear
   still reveals `pk`; what an observer learns does not change.
   `WITNESS_COMMITMENT_BYTES` still moves if the bytes do. Do not
   re-derive `PL-D3`. Falsify: a `PL-` ruling whose stated scope
   includes `0x0C` *and* forbids publishing `pk`.

A firing reopener revises `WITNESS_COMMITMENT_BYTES` in the Q13 row —
one edit, one place — not a new row.

**Does not:** implement the hash; mint a `CEN-` id; add the TSV row
(Slice C); reopen `PL-D3` on the FCMP leaf; land code. The tag is no
longer sequenced behind F5.

**SUPERSEDED:** "Q12 is sequenced behind F5 / `PL-D3`" (right in shape,
wrong in conclusion); arguing as if F5 were still an open round (the
2026-09-16 F5 agent brief, WITHDRAWN §1.5); `PL-D3a`'s `cSHAKE256(pk ‖ blind)` as Q12's
default; hiding as a purchasable upgrade for an object that publishes
`pk`; "a published hash of a low-entropy value is a lookup table" as
F5's attack; "Q12 revises the 32" as if hiding were expected; reopener
(1) as "if `h` leaves the kept side" without the concealment
criterion; count-pin +1 in this docs PR.

---

## 8. Slice C — implementation plan (NOT AUTHORIZED; written so it can be built when ruled)

**Home is Rust, and only Rust (Q15, 2026-09-16).** `20-rust-vs-cpp-policy`
and DRS-D12 agree: everything that computes lives in `shekyl-chain-rules`
(admission / epoch-mismatch / membership / deadline / witness / tag
content — new `CEN-` rows, ids at Slice C) and
`shekyl-archival-retention` / `shekyl-crypto-pq` (urn, cache, settle fold,
witness derivation). C++ is not a marshaling shim for this work; it is
not a consumer. The LMDB daemon keeps today's beacon / `h_close` / seal
gates until `shekyl-chain-rules` is the live validator.

| Item | Plan |
|---|---|
| **Where the enumeration walk goes** | `DrawableSet::at_epoch_open(view, E)` in `shekyl-chain-rules` (Q3 RULED, §7.4) seeds the cache. Writer: `shekyl-archival-retention::settlement::settle_epoch_rows(issued: impl Iterator<(DrawablePair,u32)>, passes: impl Fn(&DrawablePair)->u32) -> Vec<(ArchivalPairEpochKey, SettlementRow)>` — pure, testable, no storage. `issued` from a streamed urn replay at the slash pass over the re-walked `D` (`SO-D8d` §6.3 item 2, `SO-D8e` item 4 — the cache is dropped at `h_close + W₂` and settlement never reads it). *SUPERSEDED: `EpochAssignmentCache::issued_histogram()`; "if not resident."* Per drawn pair, `holds_shard_of` at the fire height: not held ⇒ write no row (Q3 §7.4 (3.3)). The Rust apply/slash path (S-ARCH, DRS-E4) calls it and writes the rows **before** the fold, per `SO-D7`. No FFI; no C++ loop. |
| **How `issued` is obtained** | From the urn (§7), never from records. **`SO-D8d` restates `SO-D1` §4.2 so it is not re-proposed:** an absent record would read as never-issued, which is the free-exit hole the scheme exists to close. |
| **How `passes` is obtained** | The S-ARCH `archival_serve_credit_pass_count(P,s,E)` read — a per-pair-epoch count over the `PC-D4` widened key; **complete at `h_close(E) + W₂` and therefore at the slash pass** (`10,000 ≥ 500`). Same count, same table, Rust store. |
| **Where the emission gather goes** | Same hook, same pass (§5): `gather_archival_emission_epoch_snapshot` is called from the Rust slash pass after the writer, not from epoch-close. The invariant-2 joint pin moves with it. |
| **Settlement integrity (`SO-D8d` RULED, amended 2026-09-16)** | Three local layers at the Rust slash-pass writer, none on chain: (1) each record at `(P,s,E,h)` must equal the writer's `assignment(h)` — streamed replay, not a materialised epoch; (2) **persisted** local 32-B digest of `D`, written in the connect batch at `h_open(E)` (undo-logged), compared against a **re-walk of `D` at every slash pass** (§7.4; conditional on its churn benchmark, fallback = compare only when non-resident); (3) `passes ≤ issued` FATAL as backstop (strictly dominated — §6.1). The harmful direction (`NonObservation → Missed`, and the free exit) is layer 2's alone. Desync is a **store-invariant Fault** with a new `SI-` row (minted at Slice C) — `poison().arm(row)` → `ConnectState::Halted`; never a `CenRow`, never `InvalidBlock`, never clamp, never skip. The block at the slash height is not written on this node *because the writer halted*, not because it is invalid. On-chain `D`-digest **REJECTED** (four grounds; ground 3 withdrawn). Counting `issued` from records **REJECTED**. Layers 1–2 and the SI row land with Slice C; layer 3 already exists as `SettleError::MorePassesThanIssued`. |
| **Admission changes (new `CEN-` rows in `shekyl-chain-rules`, not `blockchain.cpp`)** | Parse `h` (new kept field); admit only if `h_incl − CHALLENGE_RESPONSE_BLOCKS ≤ h < h_incl` **and** `ChainView` has `block_at(h)`. `h_incl` is the candidate's height (`tip + 1` on connect), so a response to the immediately preceding block (`h = tip`) is in range. **`h ≥ tip` as a refusal is SUPERSEDED** — it would reject that valid case. `block_hash(h−1)` from `ChainView` for the leaf index; `settlement_epoch_at_height(h)` is `SO-D9` (i); `is_assigned(h, P, s)` against the in-process cache; witness check takes `h`'s coinbase witness tag bytes + the pruned witness pk/sig + the record preimage. Dedup: `archival_serve_credit_present(P,s,E,h)` exact-get replaces the `pass_count > 0` probe. The fire-height path is deleted; `ERR_CREDIT_DEADLINE` rebinds to the `W₂` window. Each refusal is a typed `InvalidBlock { rule: CenRow, … }` (CHAIN_RULES G3). Negative fixture per row (CHAIN_RULES §8). |
| **Witness key (Q8 RULED; Q13 RULED; Q12 RULED)** | `shekyl-crypto-pq`: `derive_witness_keypair(combined_ss)` from coinbase output 0, existing `HKDF_SALT_OUTPUT_DERIVE`, new labels `LABEL_WITNESS_PQC` / `LABEL_WITNESS_ED25519`, **info without `output_index`** (registry mechanism 2, review duty). Commitment written under **`TX_EXTRA` tag `0x0C`** by the Rust miner-tx constructor; `combined_ss` never crosses the FFI. Fresh `tx_key` per block is a **derivation requirement** with a same-address / distinct-`tx_key` fixture (§7.5 P2), not a KEM inheritance. **Q12 RULED (§7.9):** the 32-B value is a bare `cSHAKE256` of the canonical witness pk under `shekyl/archival-witness-key-v1` (mechanism 1; TSV row + census pin `30 → 31` at Slice C; **not** `PL-D3`'s `pqc_key_scalar`). Independent of F5: hiding is theater because the reveal publishes `pk`; the join identifies `h`'s coinbase, not a miner identity. Reopen if `h` is removed in order to conceal the issuing block. Content rule (Q13 RULED, §7.8): one `CEN-` row, five fixtures, genesis-unconditional; dedicated parser must not copy `0x0B`'s empty-set; length is `WITNESS_COMMITMENT_BYTES` = 32; modelled on #745's `check_pqc_leaf_entries` — no FFI adapter. Q13 does not re-open optionality. **SUPERSEDED: extend `0x0B`; sequenced behind F5.** Node-side (Q10 RULED): a memory-only `ZeroizeOnDrop` ring of 32-B seeds keyed by height, Rust-owned; capacity `W₂` = 500, depth tracks fill-to-inclusion; evict on inclusion; file promptly. Orderly shutdown logs remaining depth then drops; unclean restart logs that in-flight count is **unknown** (capability limit, not error). Persist-encrypted **REJECTED**. A persisted cardinality beside the datadir is also refused (new at-rest surface for a log line; a crash still loses it unless fsynced on every fill). Re-derivable `tx_key` is the named fallback, not built. |
| **Batching (Q9 RULED, amended 2026-09-16)** | Set-commitment batching: one pk + one signature per carrier over `cSHAKE256_32` of the length-framed records in vin order (§7.6.1, bytes PROPOSED); no inclusion paths. **Carrier fail-whole** (§7.6.2 (B), RULED): one failing member refuses the carrier naming it; the witness refiles the honest members within `W₂`. Dedup stays `(P,s,E,h)` per record; a batch is a carrier, not a unit of credit. Admission of a record proves membership in a set that witness authored, not completeness. Class is `serve_credit_only` (fee-less by construction). Each carrier still obeys `TX_WEIGHT_LIMIT` = 149,400; at maturity 97 draws split 42 / 42 / 13 (≈ 347 KB/block; 42:1 amortization; +10.8 KB witness vs a single carrier). Inter-carrier blast radius is 42; `W₂` is resubmission headroom. Partition leaks nothing. Cap-raise (~11 KB/block ≈ 2.8 GB/year) and unpaid inclusion are a fee-and-weight round (FOLLOWUPS row), not this row. *SUPERSEDED: Merkle-root batching; "fail-whole refused"; 39 / 39 / 19.* |
| **Cost** | One epoch replay per settled epoch — **always**, under `SO-D8d` §6.3 item 2 (the cache is dropped at `h_close(E) + W₂`; Q7 collapsed) — 1.09 s here, Pi-4 owed, streamed; plus the §7.4 `D` re-walk, `O(holdings changes since h_open)`, benchmark owed. Both inside connect phase 9 at the slash height, once per 10,000 blocks, off the admission path. *SUPERSEDED: "if the cache is not resident."* Admission: `O(1)` ring lookups + one hybrid verify per **carrier** (unbatched would be 97 ML-DSA-65 verifies per block — itself a reason to batch). Row writes: one per pair with `issued ≥ 1` (~324,000 × 51 B ≈ 16.5 MB per epoch at maturity, pruned at `MAX_CLAIM_AGE_W`). |
| **Reader precondition (`SO-D7`'s lag)** | Rows for `E` are absent until the slash pass at `h > h_slash_deadline(E)`; the window walk must **exclude** `E` until settled, not read absence as non-observation. Under R-B the *pass* table is also incomplete for `E` during `(h_close(E), h_close(E) + W₂]`, so the interim `> 0` presence read is wrong for one more reason during those 500 blocks. Stated as a reader constraint and tested (§10 item 5). |
| **Evidence plan (`ARCHIVAL_SETTLEMENT_WRITER.md` §10)** | Items 1, 2, 3, 6 unchanged. **Item 4 restated:** *a pass drawn at epoch-relative 9,999 and included at epoch-relative 400 of `E+1` is counted for `E`*. Its red edit — the **mutation that must turn the test red**, not the implementation — is to evaluate `SO-D9` at `h_incl` instead of `h`: that asserts the including block's epoch, `E+1`, and the vector must then be refused as typed `InvalidBlock { rule: CenRow, … }` (the `SO-D9` row; **not** the FFI `EPOCH_MISMATCH` code on the LMDB tautology path). Green requires `settlement_epoch_at_height(h)` (§2.1 item 3, §3). **Item 5** as above. **New 7:** membership — a record citing an `h` at which `(P,s)` was not drawn is refused; red edit: delete the gate. **New 8:** collusion — records for one pair from a miner that won two *unassigned* heights settle **NonObservation/Missed**, never Served. **New 9:** deadline — a record with `h_incl − h = W₂ + 1` is refused, `= W₂` admits. **New 10:** witness — a record whose witness pk does not hash to `h`'s coinbase commitment is refused; a valid record re-signed under another block's witness key is refused. **New 11:** reorg — pop `h_incl`, reconnect on an alt suffix that keeps `h`: the record is gone, `h`'s draws are intact, re-inclusion admits. **New 12 (§7.5 P2):** uniqueness — two miner-tx constructions to the same payout address with independently generated `tx_key`s yield distinct `0x0C` commitments; identical `(combined_ss)` yields the same witness key. Red: a constructor that reuses `tx_key`, or drops it from the KEM IKM, makes the two commitments equal. **New 13 (§7.6.2 (B)):** carrier — a carrier whose set commitment covers one mutated member is refused whole, naming member `i`'s predicate; the honest members refiled in a later carrier within `W₂` admit. Red edits: measuring the refiled carrier's deadline from the first carrier's `h_incl` instead of `h`; admitting a carrier with zero verified members (the free-weight channel (A) was rejected for); a commitment form under which reordering or re-framing two different sets yields one byte string. **New 19 (§7.6.1):** the set-commitment KAT — four vectors: `n = 1`; `n = 2`; a collision pair (two distinct sets with byte-identical unframed concatenations, distinct commitments — the only vector that goes red when framing is dropped); a short-record vector crossing the 128-B varint boundary. Red edits: drop the framing (vector 3 only); a fixed-width or big-endian length (vector 4); a changed customization (all). **New 20 (§7.6.2):** an `n = 0` carrier is refused as a structural check, before any member predicate runs. **New 14 (§7.7):** restart — a node that produced `h`, stashed the seed, and is **orderly-shutdown** before inclusion, logs the remaining ring depth then drops, and does not answer those heights; an **unclean** restart logs that in-flight count is unknown (ring empty). Persist-across-restart (key file **or** a persisted cardinality) is the red edit. **New 15 (§7.8):** `0x0C` content — five fixtures of one row: (a) exactly one `WITNESS_COMMITMENT_BYTES` field on coinbase admits; (b) tag absent from coinbase refuses (red: `0x0B` empty-set convention); (c) two `0x0C` fields refuse (red: `find_tx_extra_field_by_type` first-wins); (d) length ±1 refuses (red: a minimum instead of exact); (e) `0x0C` on a non-coinbase tx refuses that tx (red: known-tag tolerance). **New 16 (§7.9):** named-hash — `0x0C` bytes equal `cSHAKE256(canonical witness_pk, custom=shekyl/archival-witness-key-v1)`. Red: a hiding Pedersen opening (theater: pk is still published), or a different customization. **New 17 (`SO-D8d`):** seed an admission-side urn from `D` as built at `h_open` and a settlement-side urn from a `D` **re-walked from divergent journals**; show the fold refusing through the Fault path (`poison().arm(<SI- row>)` → `ConnectState::Halted`, reads open). Must run the re-derivation, not the resident cache. A unit test of `settle_epoch(3, 2)` is **not** this fixture. Red: skip (write no row — `SO-D5` inversion), clamp (`min(passes, issued)`), an `InvalidBlock` verdict, or a persisted latch. **New 18 (`SO-D8d` §6.1):** the over-derived case — `issued_true = 1`, `issued_derived = 2`, `passes = 1` — is caught by layer 2's digest mismatch and by nothing else; red edit: skip the re-walk when a cache is resident. |
| **`CEN-L8` promotion path** | Census already homes settlement in the slash pass (`CONSENSUS_RULE_CENSUS.md` CEN-L8, corrected 2026-09-12 against `SO-D7`); the production caller is ruled-blocked on `SO-D8`, not missing-from-the-row. Path: (1) this ruling lands → (2) emission gather joins the slash pass (`SO-D8c`; invariant-2 joint pin) — the close hook stays for budget freeze, not gather → (3) writer + gather call sites land with the gates on S-ARCH → (4) `DRS-P0f` re-reviews against the merged sha and records CHECKED-CONFORMANT. Not before step 3. **SUPERSEDED:** "re-word the census row off epoch-close" as a live task — `SO-D7` already did that. |
| **What changes at the same cutover** | **Added:** `SO-D9` (i) at `h`; membership gate; deadline re-bound to `W₂`; witness authentication; `h` on the kept wire; new coinbase tag; dedup exact-get on `(P,s,E,h)`; set-commitment batching of serve-credit records (Q9, amended) — one pk + one sig per carrier over the length-framed record set, no inclusion paths; carrier fail-whole with resubmission inside `W₂`; memory-only witness-seed ring (Q10; persist-encrypted REJECTED); `0x0C` content rule (Q13; one CEN row, five fixtures, genesis-unconditional); bare-hash witness commitment (Q12; `cSHAKE256` under `shekyl/archival-witness-key-v1`); `SO-D8d` three local integrity layers (assignment equality, persisted local `D`-digest + re-walk at the slash pass, `passes ≤ issued` backstop; store-invariant Fault with a new `SI-` row, not a verdict); one local 32-B digest cell per epoch (rule-42 schema snapshot moves). **Deleted:** `challenge_fire_height` path, `ERR_FIRE_NOT_REACHED`, `ctx.block_hash_at_seal`; `archival_baseline_observed_at_epoch` as the interim `issued`; the `h_close` bound as a deadline. **Moved:** emission gather to the slash pass. **Superseded in-line (rule 23):** `PC-D2`; the `constants.rs:59` doc string becomes true and stays. |

**Sequencing against DRS — SUPERSEDED 2026-09-16 (Q15), amended same
day.** *Superseded text: "none of the above blocks on redb, and none of
it thickens the C++ beyond marshaling. If redb's `apply_block` lands
first, the FFI half is simply never written."* DRS-D12 turned the if
into the ruling. **S-CHAIN-W increment 3 landed 2026-09-15** (PR #757
merged 2026-09-16); the store has `connect`/`pop` on the branded batch.
The daemon still opens LMDB only. `shekyl-chain-rules` is scaffold
without rule bodies. **UPDATE 2026-09-16 (`dev@5fde3b1ce`):** #761 and
#762 (E6 slice 1: `Rule`/`BlockRule`, CEN-B1/B2/B7, `RuleSet` with
`held_by_cxx` rows) and #764 (S-CHAIN-R `chain_reads`; `BatchView`
implements `ChainView`; `connect` takes `ChainValid<'id, BatchView>`)
have landed since. **The falsifier is unchanged and has not fired:**
LMDB still serves production, and `held_by_cxx` rows mean the validator's
verdict still rests partly on C++ tests. Nothing moved the hold; nothing
lapsed it. Two preconditions, both named, both falsifiable — and the six
gates do **not** all wait on the second:

1. **`shekyl-chain-rules` is the live connect validator** — `ChainValid`
   minted only by that crate, no C++-verdict shim (DRS-D12 (ii)). E6
   increment 1 (scaffold) landed 2026-09-15; increment 2+ is the rule
   bodies. Deadline, SO-D9, and the `0x0C` content rule (Q13) are
   **surface-free** and ride an E6 increment whenever E6 takes them.
   Witness verification is
   surface-bound to the **block/tx** surface (coinbase `tx_extra`),
   nearer than S-ARCH. Falsify: `ChainValid` constructed from a C++
   return code.
2. **S-ARCH (DRS-E4) has ported the settlement write path** — today's
   `set_archival_settlement` four-tuple is still LMDB-only production
   (known-unwired, `DAEMON_REDB_STORE.md` §3.5). Membership against
   `assignment(h)` and dedup `(P,s,E,h)` exact-get are the two gates
   that wait here, with the writer call site. S-ARCH remains priority 7
   of 9 and gated on the P0b journal audit — **UPDATE 2026-09-23: that gate
   lifted 2026-09-05 (P0b RECONCILED) and was re-read by S-ARCH's Round-0
   pre-flight ([`DRS_E1_SARCH.md`](DRS_E1_SARCH.md) §0, PR #840), which
   splits the row: the *reads* are E1 increment 8, ruled and cuttable; the
   settlement *write path* this item waits on is E4's, whose first question
   the pre-flight names (SAR-7)** — that is **not** "waiting for
   essentially the whole port." Falsify: a production caller of the
   settlement write on the Rust apply/slash path.

Until both, the LMDB daemon's beacon / `h_close` / seal gates stay, and
Slice C is not authorized. The wait's load-bearing reason is
**re-derivation plus a second bite at a genesis-frozen wire** (Q15
header), not only the shim prohibition. The settlement methods are
**not** on the S-ARCH method list today (the table was born after that
census); they join that row when E4 is scoped — DRS inventory, not an
SO family.

**Sequencing against `PL-D3` (#745) — DISCHARGED 2026-09-14 (merged).**
Nothing above touches the leaf, `0x07`, `pqc_auths`, the circuit or the
FCMP++ public-input list; the only contact is the premise — `PL-D3`
holds because the per-output key is published once, at spend, and
**`SO-D8` must not be the second publication**. Q8's non-output witness
key is what keeps that true. `PL-D4` is V4 and changes the commitment
mechanism, not the reveal-once premise; `SO-D8` does not need to know
about it.

---

## 9. Dispositions

| ID | Disposition | State |
|---|---|---|
| `SO-D8` (parent) | Premise **stands** (§1). Shape **R-B** adopted: the record names and validates its issuing block `h`; `E = epoch(h)`; deadline `h_incl ≤ h + W₂`. `PC-D2` reversed (F4). | **DIRECTION RATIFIED 2026-09-13**; `SO-D8a`–`e` **RULED 2026-09-16**; Q3, Q8, Q9 (amended same day), Q10, Q12, Q13 **RULED 2026-09-16**; Q9 commitment bytes PROPOSED |
| `SO-D9` (standalone) | `ERR_EPOCH_MISMATCH` is a tautology. **(i)**: the record's epoch equals `settlement_epoch_at_height(h)` of the validated issuing block. Lands as a `shekyl-chain-rules` row with the R-B cutover (Q15); not a C++ one-liner. FOLLOWUPS row carries it. | **RULED 2026-09-13 — (i)**; site **re-homed 2026-09-16 (Q15)** |
| `SO-D8a` | Boundary rule `E = epoch(h)`; `ERR_FIRE_NOT_REACHED` dies; **`h_close` deadline replaced** by the per-challenge `W₂` bound. Transcription of the R-B ratification. First admission-path reader of `CHALLENGE_RESPONSE_BLOCKS`; that FOLLOWUPS row **discharged**. | **RULED 2026-09-16** |
| `SO-D8b` | Dedup **widens** to `(P,s,E,h)` exact-get; membership against `assignment(h)`. Exact-get resolves because `h` is in the past and in the DB — what `PC-D4` could not do. Served by `SO-D8e`'s `W₂` ring (RULED 2026-09-16); the key and predicate ruled here, the structure there. | **RULED 2026-09-16** |
| `SO-D8c` | Emission gather **moves to the slash pass** — `SO-D7` applied to its second consumer; invariant-2 joint pin moves with it. Presence-vs-absolute-2 recorded, not opened. | **RULED 2026-09-16** |
| `SO-D8d` | Three **local** layers, none on chain: (1) per-record assignment equality against the writer's `assignment(h)`, streamed; (2) **persisted** local 32-B digest of `D` written in the connect batch at `h_open(E)` (undo-logged), compared against a **re-walk at every slash pass** (option (b); conditional on §7.4's churn benchmark; fallback (a) stated); (3) `passes ≤ issued` FATAL backstop, **strictly dominated**. Guards Q3 reconstruction, not arithmetic. The harmful direction (`NonObservation → Missed`; the free exit) is layer 2's alone — layer 1 cannot see a count divergence (§6.1). Desync is a **store-invariant Fault** with a new `SI-` row (Slice C), never `CenRow`/`InvalidBlock`; block at the slash height unwritten *because the writer halted* (§6.4). Q7 **collapsed**: cache drops at `h_close + W₂`. Pin 4 reconciled by call site. Clamp and skip **FORBIDDEN**. On-chain `D`-digest **REJECTED** on four grounds — **ground 3 WITHDRAWN**. Counting `issued` from records **REJECTED** (`SO-D1` §4.2). Four falsifier classes at the site (dedup revert; reconstruction perturbation; journal prune — fires upstream; λ divergence — Q4 is a coverage precondition). Fixture 17 runs the re-derivation; fixture 18 pins the over-derived case. Served-artifact `D` carried against PDM. | **RULED 2026-09-16; amended 2026-09-16 vs `dev@5fde3b1ce`** |
| `SO-D8e` | `EpochAssignmentCache`: forward-advancing `ChallengeUrn` plus a `W₂` ring of self-contained `(p_id, shard_id)` outputs (`≈ 1.9 MB`); membership gate reads the ring, `O(1)`, refuse outside it. **No checkpoints** — rewind replays from the wave boundary (`remaining == 0` resets `working`; boundaries are `⌊(h+1)·total/E⌋`, hash-independent). **One `DrawableSet` live** — only the ring spans the epoch boundary. Lifetime `[h_open(E), h_close(E) + W₂]`, then dropped; settlement never reads it (Q7 collapsed). One carve-out to never-persisted: the 32-B `D` digest in the connect batch at `h_open(E)` (undo-logged; `digest_v0` excludes it by construction). ~16 MB at maturity. Reorg: fork at/above `h_open` — `D` untouched (post, re-bond, drop, release, slash each verified at source), replay one wave (~0.36 s); fork below `h_open` (first 720 blocks, `ARCHIVAL_REORG_DEPTH_BLOCKS`) — rebuild `D`, urn, digest. Records survive reorgs verbatim. Stateless draws-with-replacement **FORECLOSED** (≈20 % unobservable at λ = 3; invalidates absolute-2). Wave-tail warning window recorded, not fixed. Owed: `SI-10` for `SO-D8d` (SI-5 exists, ruled-unbuilt; reuse refused); 720 not `D_max`. λ from the constant (Q4). Rust apply/pop path only; no FFI (Q15). *SUPERSEDED: checkpoints; two `DrawableSet`s; retain through the slash deadline.* | **RULED 2026-09-16** |
| Drawable set (Q3) | `DrawableSet::at_epoch_open(view, E)` in `shekyl-chain-rules` over `ChainView`; no snapshot table. A dropped pair stays in `D`; filter at settlement and witness. Construction §7.4. | **RULED 2026-09-16** |
| `W₂` (Q2) | Under R-B `CHALLENGE_RESPONSE_BLOCKS` **is** the per-challenge deadline and the const-assert coupling it to `CHALLENGE_RESOLUTION_BLOCKS` is load-bearing (§5 depends on it). FOLLOWUPS row **discharged 2026-09-16** by `SO-D8a` RULED (first admission-path reader). | **RESOLVED by R-B**; referent **RULED 2026-09-16 (`SO-D8a`)** |
| Witness key (Q8) | **Dedicated non-output hybrid key** derived from coinbase output 0's `combined_ss` under `HKDF_SALT_OUTPUT_DERIVE` + `LABEL_WITNESS_PQC` / `LABEL_WITNESS_ED25519` (no `output_index` in info); 32-B commitment under **`0x0C`**; pk + sig pruned. Combined_ss stays in Rust. The coinbase output's own per-output key is **ruled out by `PL-D3`'s premise**. **SUPERSEDED: extend `0x0B`.** Q13 RULED (§7.8) owns the CEN wording: **mandatory-present** (commitment 2, not byte count); **fresh `combined_ss` per block** is a derivation requirement with a fixture, not a KEM inheritance. Q10 RULED: `W₂` ring is memory-only, restart loss is β. Q12 RULED (§7.9): bare 32-B `cSHAKE256` under `shekyl/archival-witness-key-v1`; hiding is theater (reveal publishes `pk`); reopen if `h` is removed **in order to conceal** the issuing block. Construction §7.5. | **RULED 2026-09-16** |
| Batching (Q9) | **Amended 2026-09-16:** set-commitment batching — one pk, one signature per carrier over `cSHAKE256_32` of the length-framed records in vin order; **no inclusion paths**. **Carrier fail-whole + resubmission within `W₂`** (§7.6.2 (B) RULED; (A) per-vin admission REJECTED — free-weight channel). Dedup stays `(P,s,E,h)` per record. Serve-credit is fee-less by construction. 300,000 is `get_min_block_weight` (a floor). Prunable bytes count toward weight. Against `TX_WEIGHT_LIMIT` the 97-record set splits 42 / 42 / 13 (≈ 347 KB/block; 42:1). Inter-carrier blast radius 42; `W₂` is resubmission headroom. Partition leaks nothing. Unpaid inclusion, prunable-weight discount, cap-raise → fee-and-weight round (FOLLOWUPS row). Construction §7.6; bytes §7.6.1 (PROPOSED: one cSHAKE256 under `shekyl/archival-serve-credit-batch-v1`, KAT at Slice C). *SUPERSEDED same day: Merkle-root batching with per-record inclusion paths — its isolation-at-admission premise was false under the carrier contract, and resubmission (mandatory for reorgs anyway) provides the isolation for 22 KB/block less.* | **RULED 2026-09-16 (amended same day)**; commitment bytes **PROPOSED** |
| Secret lifetime (Q10) | Accept loss. Memory-only `ZeroizeOnDrop` ring of 32-B seeds; persist-encrypted **REJECTED** (daemon has no passphrase; rule 36 §3 is a wallet envelope). File promptly; evict on inclusion; log dropped in-flight on restart. Named fallback: re-derivable `tx_key` from a long-lived node secret and `h` — not persist; reopens if a sim of restart-to-restart vs fill-to-inclusion shows batches routinely dragging toward `W₂`. Construction §7.7. | **RULED 2026-09-16** |
| `0x0C` content (Q13) | One `CEN-` row (id at Slice C), one predicate, five fixtures. Exactly one entry, length `WITNESS_COMMITMENT_BYTES` (32; Q12 RULED; a reopener revises the constant), coinbase only, **present**, from genesis. Dedicated parser must not copy `0x0B`'s empty-set. First-wins is the red edit for duplicates. Surface-free; E6-landable. Construction §7.8. **SUPERSEDED:** four rows; copying the `0x0B` parser; unread 600-byte extra ceiling. | **RULED 2026-09-16** |
| Slice A1 (Q6) | **Keep**, per review, on grounds narrower than §12 gave. | **ANSWERED — keep** |
| F3 | First cut's F1 row 1 cited the attestation path for the vin's binding; corrected at source. **SUPERSEDED 2026-09-16 (Q9):** the surviving half — "who pays the fee" — there is no fee, and there cannot be one (`serve_credit_only` is non-spending; `txnFee != 0` is a refusal). | **CORRECTED**; fee-half **SUPERSEDED** |
| F4 | `PC-D2` ↔ mechanism §2 contradiction; `PC-D2`'s herd premise inverted; reversed by R-B. In-line supersession at `PC-D2` owed with the ruling PR. | **RECORDED** |
| **F5** → `PL-D1` | **Every FCMP++ spend is linkable to its output by the public 4th leaf scalar.** Tree-wide, pre-genesis, priority-2. Opened by Rick as the `PL-` round 2026-09-13/14; **CLOSED by `PL-D3`** (hiding Pedersen commitment opened in-circuit) in PR #745, **merged 2026-09-14**; `PL-D4` (hash mechanism) at V4. This proposal's FOLLOWUPS line withdrawn 2026-09-14 per `PL` §12 ruling 11. **The 2026-09-16 F5 agent brief is WITHDRAWN, not amended (§1.5).** Decision procedure for a published per-object commitment, in order (§7.9): (1) enumerable preimage? (2) does the reveal publish the preimage? (3) does the join identify more than the reveal was entitled to? F5 fails (3) and passes (2) only because the circuit opens without revealing (`PL-D3` reveal-once). Q12 fails (2) — ML-DSA verify requires the key — so hiding is theater and a bare hash is correct. Do not re-derive `PL-D3`. | **CLOSED by #745 (merged)** |
| Sweep on ruling | `constants.rs:59` W₂ doc (becomes true — keep); `ARCHIVAL_SETTLEMENT_WRITER.md` §6/§12/§13 and the `IMPLEMENTATION_INDEX.md` SO-row `SO-D7` lag sentence (become true — re-date); `PC-D2` and its citations (`ARCHIVAL_PER_CHALLENGE_RECORD.md`, `TJ` `:819–822`) marked SUPERSEDED in-line; `FCMP_PLUS_PLUS.md:102–104,:121–122`, `POST_QUANTUM_CRYPTOGRAPHY.md:735–737`, `MERKLE_TREE.md:235` — **F5's sweep, DONE by #745 at source** (`PL` §11; the `REWARD_EMISSION_LEG.md` §7.3 tripwire marked FIRED there too). | owed with the ruling PRs (`PL` half done) |

### 9.1 Figures flagged for re-derivation

| Figure | Source | Status 2026-09-13 |
|---|---|---|
| ~972,000 assignments / epoch | `CHALLENGES_PER_PAIR_PER_EPOCH × 324,000`, `measure_full_epoch_replay_cost_at_maturity` | **Holds** as `λ·pairs`; since Q4 (2026-09-17) `λ` is the constant, read at the urn's entry points and in the measurement test. *SUPERSEDED: "`λ = 3` is a test parameter, not a pinned constant."* Cost **measured** 1.09 s release on this host; Pi-4 owed. |
| ~97 draws / block at maturity | `972,000 / 10,000` | Arithmetic; the per-block witness load and the ring size derive from it. |
| 72 % unobservable at `k_cap = 30` | `ARCHIVAL_CHALLENGE_MECHANISM.md:1185` histogram `{0: 35 %, 1: 37 %, 2: 28 %}` | **Not re-derived** — doc-only figure, no code artifact. Under R-B the capped-regime mechanics are unchanged (the window changes when a draw is answered, not how many are drawn). Flagged *unverifiable at source*. |
| ~3,411 B record; 5,107 B pre-`RF-D6` | `ARCHIVAL_RESPONSE_FORMAT.md:1012`, `cryptonote_config.h:432–433` | 3,411 B is the post-`RF-D8`-retraction record; 5,107 B is `ARCHIVAL_SERVE_CREDIT_PRUNED_RECORD_BYTES` (today's pruned-weight reconstruction constant). R-B adds `h` (≤ 10 B kept) and the witness material (1,996 + 3,385 B pruned, once per carrier; no per-record path bytes under the amended Q9; 42 records per carrier against `TX_WEIGHT_LIMIT`). |
| 1,996 / 3,385 B hybrid key / sig | `cryptonote_config.h:386,:388` | **Grounded.** (Was cited `:396,:398` — line drift.) |
| 850 KB / 335 KB per block | §2.1 item 8 / §7.6 | Arithmetic on the grounded figures; **provisional on `D ≈ 324k`**. Against the inherited cap the set splits 42 / 42 / 13 (no path bytes, 3 × 5,381 B witness) → ≈ **347 KB/block**. *SUPERSEDED: Merkle extra ≈ 22 KB; 39 / 39 / 19 → ≈ 365 KB.* **SUPERSEDED:** "300 KB penalty-free zone" — 300,000 is `get_min_block_weight`, a floor (`cryptonote_basic_impl.cpp:81–85`). Prunable-in-weight **confirmed** at `cryptonote_format_utils.cpp:323–334,:374–379`. Cap-raise vs a single 97-record carrier ≈ 11 KB/block ≈ 2.8 GB/year — fee-and-weight round. |

### 9.2 Wargames under R-B

| Scenario | What happens | What stops it |
|---|---|---|
| **Adaptive-selection archiver** — `P` serves only when it can predict it is assigned | `assignment(h)` is public at `h−1`; `P` can predict *that* it is drawn. But the witness is `h`'s winner, unknown until mined, who fetches within `W₂`; `P` refusing everyone but a colluding pool earns non-observation from honest winners, which under 2-of-3 with `λ = 3` is **Missed** unless the colluder wins ≥ 2 of the 3 assigned blocks. | Membership gate + witness authentication + `PC-D3` leaf drawn at `h−1`; residual priced by the quadratic. |
| **Forged issuing block** — record cites an `h` at which the pair was not drawn, or which the includer did not produce | (a) `h` outside `[h_incl − W₂, h_incl)` → deadline refusal; (b) `(P,s) ∉ assignment(h)` → membership refusal; (c) `h` real and assigned but signer is not `h`'s producer → witness hash-compare against `h`'s coinbase commitment fails. | §2.1 item 3 (a), (d), (e). |
| **Boundary-straddler** — draw at epoch-relative 9,999 of `E` | Answerable in blocks `[10,000, 10,499)` of the chain — epoch-relative `[0, 499)` of `E+1` — names `E` (`epoch(h) = E`), counted for `E`, present in the table by `h_close(E) + 500`, read by the writer and the emission gather at `h_close(E) + 10,000`. | `SO-D9` (i) at `h`; §5's move; `CHALLENGE_RESOLUTION_BLOCKS ≥ CHALLENGE_RESPONSE_BLOCKS`. |
| **Reorg across `h_close(E)`, or across `h`** | Suffix property (§2.2): no connected record can reference a removed `h`. Alt branch's blocks carry their own records (leaf index bound to their own `h−1`); losing branch leaves no residue. Settlement rows for `E`, if written, are deleted by `revert_archival_slashes_at_height` and recomputed on reconnect (`SO-D6`); cache and ring rewind together. | `SO-D6` + §7.2. **Unread, named:** the pop order in `blockchain_db.cpp:748–749` reverts slashes before epoch-close; confirm the cache rewind is sequenced before either. |
| **Witness key loss** — producer of `h` restarts and loses the witness seed | Draws at those heights that have not yet been included fall to non-observation; nothing errors. Shows up as β, which MECHANISM §7 item 7 requires treating as **common-mode**. Always-present (Q8 P1) means ring *capacity* is 500; steady-state depth is fill-to-inclusion. | Q10 RULED: accept loss; log the dropped in-flight count. Persist-encrypted **REJECTED**. Named fallback is re-derivable `tx_key`, not persist. Not a consensus concern; an availability one. |
| **Reused coinbase `tx_key`** — encapsulation deterministic over a fixed payout | Two blocks share `combined_ss`, share the witness key, `0x0C` blobs match: a cross-block miner identifier, which is what the dedicated key exists to avoid. | §7.5 P2: constructor must use a fresh `tx_key` per block; Slice C fixture 12 fails if uniqueness is inherited from "the KEM is random". |
| **Batch as single point of failure** (Q9 RULED, amended) | One carrier carries many credits and is fail-whole: one corrupt record refuses the carrier for its honest members — but with `W₂ = 500` that is a **round-trip**, not a loss; the witness refiles without the bad member. Underfunded is not the vector: there is no fee. Unrelayed / omitted at the median is the residual (miners voluntarily carrying zero-fee data); a dynamics question for the fee-and-weight round, not a Q9 ruling. **Inter-carrier:** three independent inclusion decisions; taking 2 of 3 costs 42 archivers that inclusion. A witness that wants to deny credits does not witness, at zero cost, under any form. Partition leaks nothing. | Resubmission within `W₂` (mandatory machinery anyway — orphaned records are re-submittable verbatim, §7.2). Dedup stays per-record. Subset filing ≡ not witnessing those pairs, a power the witness already has. *SUPERSEDED: Merkle inclusion (exclude the mutant, verify the rest).* |
| **Under-issuance regime** (`k_cap` binding) | Pairs with `issued ≤ 1` settle NonObservation with a row (`SO-D1`), so degradation is measured, not silent. Unchanged by R-B. | `SO-D1`/`SO-D2`'s `issued` byte. |
| **`PL-D3` interaction** (was "F5 interaction") | `PL-D3` (#745) holds because the per-output key is published once, at spend. A witness scheme keyed on a spendable output's pk publishes it a second time, labelled with `h`; the later spend is linked by byte equality — `PL-D3` void on every witnessing coinbase. Witness key derived under its own HKDF labels is independent of the sibling per-output key, `r` and `r_h`. | Q8 RULED: the non-output witness key under `0x0C`; Q13 RULED for the content rule; Q12 RULED: bare hash (§7.9), not `PL-D3` hiding. |

---

## 10. Questions for Rick

Seven were posed in the first cut; four answered in the 2026-09-13 review,
`SO-D9` ruled, and R-B ratified the same day, which resolves 1, 2 and 7. Four
new ones arise from R-B; Q11 is resolved by the `PL-` round and #745; Q12–Q13
were opened in the 2026-09-14 reconciliation; Q14 was opened by #747 review
and is resolved by Q15 (2026-09-16). **Open question: Q9's set-commitment
vectors (§7.6.1, PROPOSED — one customization and a KAT, registry row at
Slice C).** Q4 RESOLVED 2026-09-17. Q9's carrier semantics RULED 2026-09-16
(§7.6.2 (B)); Merkle-root batching SUPERSEDED the same day. `SO-D8e`
RULED 2026-09-16 (§7.2). `SO-D8a`/`b`/`c` RULED 2026-09-16 (transcriptions of R-B /
PC-D4 / SO-D7). `SO-D8d` RULED 2026-09-16 (§6), amended same day:
three local layers; persisted `D` digest + re-walk at every slash pass
(Q7 collapsed); store-invariant Fault with an `SI-` row, never a
verdict; on-chain digest REJECTED (ground 3 withdrawn). Q3 RULED
2026-09-16 (§7.4). Q8 RULED 2026-09-16 (§7.5): dedicated non-output key,
tag `0x0C` not `0x0B`; P1 mandatory-present and P2 `combined_ss`
freshness. Q9 RULED 2026-09-16, amended same day (§7.6):
set-commitment batching; carrier fail-whole + resubmission within `W₂`;
no fee; 300,000 is a floor; prunable bytes count toward weight; split
42 / 42 / 13 against `TX_WEIGHT_LIMIT`. *SUPERSEDED: Merkle-root
batching; fail-whole refused; 39 / 39 / 19.* Q10 RULED 2026-09-16 (§7.7): accept loss;
persist-encrypted **REJECTED**; named fallback is re-derivable `tx_key`.
Q13 RULED 2026-09-16 (§7.8): one CEN row, five fixtures, genesis
domain, named length constant; dedicated parser must not copy `0x0B`.
Q12 RULED 2026-09-16 (§7.9): bare 32-B hash, independently of F5.
*SUPERSEDED: sequenced behind F5.*

1. **RATIFIED — R-B.** The herd is R-A's, not R-B's (F4). Recorded §2.
2. **RESOLVED by 1.** `CHALLENGE_RESPONSE_BLOCKS` becomes the per-challenge
   deadline; the const-assert becomes load-bearing.
3. **RULED 2026-09-16 — `DrawableSet::at_epoch_open(view, E)`.**
   Pure function in `shekyl-chain-rules` over a `ChainView` projection of
   the append-only bond journals (holdings-update, unbond, reinstate, slash).
   Evaluated at `h_open(E)`. No snapshot table; seeds
   `EpochAssignmentCache` once per epoch. A drawn pair whose shard has
   been dropped **stays in `D`**; the drop filter lives at settlement and
   at the witness, not at draw. Construction, drop-stability finding,
   pins, empty-`D` and slash-vs-drop: §7.4. Body lands with Slice C.
4. **RESOLVED 2026-09-17 (`fix/so-q4-pin-lambda`).** `ChallengeUrn::new`
   reads `CHALLENGES_PER_PAIR_PER_EPOCH` and takes no λ; `assign_epoch`
   feeds that constructor. The explicit-λ constructor is `#[cfg(test)]`
   (tests need λ ∈ {0, 1, 2, `u32::MAX`}). One production site; pinned
   by `production_doors_read_the_constant_and_take_no_lambda`. The
   mechanism doc's §9.5 pin 3 ("λ_target is a parameter … supplied by the
   caller") is SUPERSEDED in place. *Records-was:* `lambda_target` was a
   bare `u32` at `challenge_assignment.rs:152` / `:264`; two independent
   `pub` doors; the first landing made them `pub(crate)`, which still
   left every non-test module in the crate able to pass a divergent λ.
   §7.2's `open()` drops the parameter and reads the constant.
   *Records-was (2026-09-16, "Two doors"):* `assign_epoch` reads the
   constant, but `ChallengeUrn::new` is `pub` and re-exported, so the
   strong form is a `pub(crate)` constructor or a documented sim-facing
   second door — say "the epoch entry point reads the constant", not "λ
   cannot be passed wrong". **`SO-D8d` makes Q4 a coverage precondition,
   not only a correctness one** (§6.5): a λ that differs between
   admission and settlement leaves the pair set identical, so layer 2
   passes; only layer 1 fires, and only on replay. Closed ahead of
   Slice C; landed in its own PR after #759 (rule 19: Rust gates, not
   docs gates).
5. **ANSWERED, then RULED.** `ERR_CREDIT_DEADLINE`'s disposition changed with
   R-B — it is **re-bound** to the `W₂` window, not kept as `h_close` (§3).
   The vacuous check was `ERR_EPOCH_MISMATCH` (`SO-D9`), ruled (i).
6. **ANSWERED — keep A1.**
7. **RESOLVED by 1; COLLAPSED 2026-09-16 by `SO-D8d` §6.3 item 2.** The
   cache must retain `≥ W₂` of per-block draws for admission regardless,
   and drops at `h_close(E) + W₂`. The writer re-derives at every slash
   pass (layer 2 cannot exist otherwise), so retention past `h_close + W₂`
   buys nothing at settlement; the writer is a pure function of chain
   data (`SO-D1` §4.2, `SO-D6`). *SUPERSEDED: "Recommendation: retain."*
   Fallback if §7.4's churn benchmark refuses the re-walk on the Pi 4:
   retention returns, layer 2 compares only when non-resident.
8. **RULED 2026-09-16 — (Witness key).** Dedicated non-output hybrid key
   from coinbase output 0's `combined_ss`, existing salt, new labels,
   info without `output_index`; 32-B commitment under **`0x0C`**. Combined_ss
   is not on `ShekylOutputData` and does not cross the FFI. The coinbase
   output's own per-output key remains **ruled out** (`PL-D3`). The
   never-spent extra output remains refused. **SUPERSEDED: extend `0x0B`**
   — no version prefix, `k × 49` B, empty = absent tag, different concern
   (included records vs issuer identity); appending 32 B fails
   `is_multiple_of(49)`. Construction §7.5. Pins Q13/Q10 inherit: mandatory-present
   (P1); `combined_ss` uniqueness is a derivation requirement with a fixture
   (P2); `W₂` ring capacity is 500 seeds, restart = β (Q10 RULED:
   accept loss). Q12 RULED (§7.9): bare 32-B hash. Q13 RULED (§7.8): one CEN row,
   five fixtures; it does not re-open optionality.
9. **RULED 2026-09-16 — (Batching); amended same day.** Set-commitment
   batching: one pk, one signature per carrier over `cSHAKE256_32` of the
   length-framed records in vin order (§7.6.1, bytes PROPOSED — one
   customization, one KAT, registry row at Slice C); **no inclusion
   paths**. **Carrier fail-whole + resubmission within `W₂`** (§7.6.2
   (B) RULED): one failing member refuses the carrier naming it; the
   witness refiles the honest members. (A) per-vin admission REJECTED —
   a new consensus semantics and a free-weight channel for the
   unpaid witness. Dedup stays `(P, s, E, h)` per record; a batch is a
   carrier, not a unit of credit; admission proves membership in a set
   the witness authored, not completeness. Subset filing ≡ not
   witnessing those pairs. There is no fee (`serve_credit_only` is
   non-spending; `txnFee != 0` is a refusal); records ride ordinary
   txs, never the coinbase. 300,000 is `get_min_block_weight`, a floor;
   the fee ladder prices against the long-term effective median, which
   archival traffic sets at maturity. Prunable bytes count toward
   `block_weight`. Each carrier obeys `TX_WEIGHT_LIMIT` = 149,400
   (inherited; split is subset filing): 97 records split 42 / 42 / 13
   (≈ 347 KB/block; 42:1 amortization; +10.8 KB witness vs a single
   carrier). Inter-carrier blast radius 42; `W₂` is resubmission
   headroom. Partition leaks nothing. Unpaid inclusion, prunable-weight
   discount, and the ~11 KB/block cap-raise belong to the fee-and-weight
   round (FOLLOWUPS row added 2026-09-16). **SUPERSEDED same day:**
   Merkle-root batching with per-record inclusion paths — chosen so a
   corrupt record could be excluded and the rest verify, a premise the
   carrier contract falsifies (one failing vin refuses the transaction
   under any signature form); resubmission, mandatory for reorgs anyway,
   provides the isolation for 22 KB/block less; the malicious witness
   does not separate the forms (not witnessing is free under both).
   Also superseded: "fail-whole refused"; 39 / 39 / 19; ≈ 365 KB; "against
   a 300 KB penalty-free zone"; "who pays the fee"; unread "prunable bytes
   still count toward block weight."
10. **RULED 2026-09-16 — (Secret lifetime).** Accept loss. Memory-only
    `ZeroizeOnDrop` ring of 32-B seeds keyed by height; persist-encrypted
    **REJECTED** (daemon has no passphrase; rule 36 §3 is a wallet
    envelope; a key file beside the data protects nothing with disk
    access). File promptly; evict on inclusion. Orderly shutdown logs
    remaining depth then drops; unclean restart (crash / OOM) logs that
    in-flight count is **unknown** — the ring is gone. Do not persist a
    cardinality beside the datadir (new at-rest surface for a log line;
    a crash still loses it unless fsynced on every fill, which is
    persist by another name). Ring *capacity* is
    `CHALLENGE_RESPONSE_BLOCKS` = 500; steady-state depth tracks
    fill-to-inclusion. Restart loss is β, and β is common-mode
    (`ARCHIVAL_CHALLENGE_MECHANISM.md` §7 item 7). Named fallback if a
    sim of restart-to-restart vs fill-to-inclusion shows batches
    routinely dragging toward `W₂`: re-derivable coinbase `tx_key` from
    a long-lived node secret and `h` — **not persist**; consensus-adjacent,
    held, not built. Construction §7.7. **SUPERSEDED:** persist-encrypted
    as the restart policy; "500 live seeds" as expected ring depth;
    "log the exact dropped count on every restart" (unclean restart
    cannot).
11. **RESOLVED 2026-09-14 — (F5)** You opened it as the `PL-` round the
    same day; `PL-D1` is the defect, `PL-D3` the fix, ratified and landing in
    #745; `PL-D4` at V4. #745 merging is discharged (§8, "Sequencing against `PL-D3`").
    *Superseded: "It gates nothing in `SO-D8` beyond #745 merging first."*
    *SUPERSEDED: "Q12 inherits F5/`PL-D3`'s commitment-shape ruling
    and is sequenced behind it."* Q12 RULED independently (§7.9). This
    proposal's FOLLOWUPS line is withdrawn; Q8's recommendation is
    re-made against `PL-D3`.
12. **RULED 2026-09-16 — (Witness commitment is a bare hash).**
    `WITNESS_COMMITMENT_BYTES` = 32, `cSHAKE256` of the canonical
    witness pk under `shekyl/archival-witness-key-v1`. Registry
    (`CRYPTO_DOMAIN_REGISTRY.tsv` mech 1) checked: slash-form matches
    live archival cSHAKE strings; no collision; TSV row + census pin
    `30 → 31` land with Slice C. Ruled on its own analysis, not as F5
    inheritance. Construction §7.9. Three questions, in order: (1)
    enumerable? No — 1,996 B, unlike `pre_shard_ids`. (2) does the
    reveal publish the preimage? Yes — ML-DSA verify requires the key;
    hiding without ZK is theater. (3) does the join identify more than
    the reveal was entitled to? No — one producer of `h`; identifying
    them is the predicate. The join identifies `h`'s **coinbase** (a
    stealth payout already in the block), not a miner entity;
    co-location of `0x0C` next to output 0 binds that whether or not
    the record names `h`. Real residual: P2 / fixture 12. Reopeners:
    (1) falsify if `h` is removed **in order to conceal** the issuing
    block (a compactness drop that leaves `h` public-by-join does not
    invert); (2) process, not analysis — a blanket hide that still
    reveals `pk` is theater; falsify by a `PL-` ruling that forbids
    publishing `pk`. Either revises `WITNESS_COMMITMENT_BYTES` in the
    Q13 row. **Hierarchy still binds:** if concealment required
    stopping the pk reveal and that weakened the binding, refuse.
    *SUPERSEDED: sequenced behind F5; `PL-D3a` hiding as Q12 default;
    F5 as a lookup-table; reopener (1) as "`h` leaves the kept side"
    without concealment intent; count-pin +1 in this docs PR.*
13. **RULED 2026-09-16 — (Tag content rule).** One `CEN-` row in
    `shekyl-chain-rules` (id at Slice C), one predicate over one field,
    five fixtures. Exactly one entry, length `WITNESS_COMMITMENT_BYTES`
    (32; Q12 RULED; a reopener revises the constant, not a new row), coinbase only,
    **present**, from genesis unconditionally. Dedicated parser
    `parse_archival_witness_commitment_from_extra` — must **not** copy
    `0x0B`'s empty-set convention (`cryptonote_format_utils.cpp:687–692`);
    absent rejects. "Exactly one" is a count;
    `find_tx_extra_field_by_type`
    (`cryptonote_format_utils.h:70–77`) is first-wins and is the red
    edit for duplicates. Predicate co-located with `0x0B`'s concern;
    site is a chain-rules CEN row at Slice C (Q15). `:5306` is
    records-was of the LMDB 0x0B read. Surface-free; E6-landable
    with deadline and SO-D9. Budget: 34 B vs occupants already on the
    coinbase (`0x0B` max 12,544 B); `COINBASE_BLOB_RESERVED_SIZE` = 600
    is a weight reserve, not an extra cap (`cryptonote_config.h:440–442`).
    Construction §7.8. Does not re-open P1. Does not mint the `CEN-` id.
    **SUPERSEDED:** four rows for four clauses; copying the `0x0B`
    parser; unread 600-byte extra ceiling; a literal `32` as the length
    clause. *Superseded: "through the same FFI adapter."*
14. **RULED 2026-09-16 by Q15 — (`SO-D9` (i) sequencing, surfaced by review of #747).** With the
    two pre-FFI bounds in place (§1, "Ordering"), (i) built alone on the
    LMDB path would change the verdict on exactly one block per epoch: a
    record for `E` in block `(E+1)·N` goes from admitted to refused, and
    R-B's `epoch(h)` operand admits it again. *SUPERSEDED alternatives
    (records-was of the pre-Q15 choice): (a) land (i) **with** the R-B
    cutover as the same C++ site (`:5304`) with its final operand, with
    an isolated FFI verifier test covering the check; or (b) land (i)
    now on `current_height` and re-target the operand in the cutover.*
    **RULED 2026-09-16 by Q15 as (a), stronger:** not merely "with the
    cutover" but *in* `shekyl-chain-rules`, never as a C++ one-liner on
    the LMDB path. The one-block flip does not ship. The isolated FFI
    test is **not** coverage of the new row. **Prohibition:** do
    not repair the tautology in `blockchain.cpp`. Making it fire is a
    consensus tightening on the live LMDB daemon for a path being
    replaced, on the shorter-lived implementation. In chain-rules it is
    a positive row with a negative fixture; the tautology never ports.
15. **RULED 2026-09-16 — (Placement)** Wait until SO can be written
    directly in Rust; no C++ mirroring. **S-CHAIN-W increment 3 is
    landed** (PR #757, 2026-09-16); DRS is one increment from a
    validator, not mid-increment. Deadline and SO-D9 are surface-free E6
    rows; witness verification is bound to the block/tx surface;
    membership and dedup wait on S-ARCH with the writer. Pre-cutover
    LMDB daemon keeps today's beacon — §5.1's interim-writer question
    stays closed. Falsify by `shekyl-chain-rules` being the live connect
    validator (`ChainValid` without a C++-verdict shim) **and** a
    production settlement write on the Rust apply/slash path. Until
    both, Slice C is not authorized. Subsumes Q14. *SUPERSEDED: Q12
    sequenced behind F5.* Q12 RULED independently (§7.9).
