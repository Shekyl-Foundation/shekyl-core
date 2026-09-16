# `SO-D8` — ruling-round proposal: cross-epoch admission and the settlement writer's production caller

**Status:** OPEN — **PROPOSAL; direction RATIFIED, sub-dispositions not yet
ruled.** Rick ratified shape **R-B** (post-issuance window, §2) on 2026-09-13
with the eight modifications in §2.1 to be ruled item by item; `SO-D9` (i) is
ruled (§1). Drafted 2026-09-13 for Rick's ratification. Nothing in the §9 table
is authority until stamped RULED; until then `ARCHIVAL_SETTLEMENT_WRITER.md`
§12's rule-22 hold on the writer's call site **stands** and this document does
not route around it. No admission code, no consensus code, and no writer call
site were written for this round (Slices A and B of the 2026-09-13 brief were
authorized; Slice C — implementation — was not, and §8 is its plan, not its
work).

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
> half is simply never written"*) is **SUPERSEDED** in place: the
> admission gates land as new `CEN-` rows in `shekyl-chain-rules` (an E6
> increment; ids minted at Slice C, next free in their family — not here);
> the writer call site lands on the Rust apply/slash path when **S-ARCH**
> (DRS-E4) ports the settlement table; C++ never learns either. The
> pre-cutover LMDB daemon keeps today's beacon / `h_close` / seal gates.
> Falsify by `shekyl-chain-rules` being the live connect validator
> (`ChainValid` minted without a C++-verdict shim) **and** a production
> caller of the settlement write in the Rust apply/slash path. Until both,
> Slice C is not authorized. Q14 is resolved by this ruling (§10).

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

- **(i) Make it fire:** populate `ctx.settlement_epoch` from
  `shekyl_archival_settlement_epoch_at_height(current_height)`
  (`shekyl_ffi.h:2594`, exists) — one C++ line — so *"the record's epoch is the
  including block's epoch"* becomes an explicit enforced rule.
- **(ii) Delete it** and let the row-5 `h_close` gate be the single expression.

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
>   knowingly (Q14); (c) the test for (i) is an **isolated verifier test**
>   (`shekyl-ffi/src/archival_ffi/tests.rs` already drives
>   `shekyl_archival_verify_serve_credit_vin` directly) with
>   `ctx.settlement_epoch` derived from height and a header that disagrees —
>   not a full-path future-epoch vector, which the seal gate would refuse
>   first and mis-attribute. The cutover that deletes the beacon gates
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
> bullet already named. The isolated verifier test still covers the check
> once the row exists; the full-path vectors (stale → deadline, future →
> seal) die with the beacon gates they live on. FOLLOWUPS row carries it.

### 1.1 What is true about `W₂`, and why it makes the round larger

`CHALLENGE_RESPONSE_BLOCKS` has **no admission consumer** — verified:
`constants.rs:171`, `:183–185`, `:194–195` are const-asserts and `lib.rs:139`
is the re-export; nothing else reads it. Its doc string — *"blocks after a
challenge's issuing block to accept its serve-credit response"*
(`constants.rs:59`) — describes a gate that does not exist. **There is no
per-challenge deadline anywhere in code.** Its value is
`SETTLEMENT_EPOCH_BLOCKS / W2_EPOCH_DIVISOR = 10,000 / 20 = 500`
(`constants.rs:147,:153,:202`) — about 16.7 hours at 2-minute blocks.

This does not shrink `SO-D8`; it removes its escape hatch. §12's argument was
*"the ruled per-challenge deadline already exists and is per-challenge"*, so
the `h_close` gate could simply be re-pointed at it. It does not exist. Under
the ratified shape R-B the round must **design** that deadline, not re-point
to it — and the constant then acquires the consumer its doc string already
describes (§2.1 item 6).

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
| `passes > issued` | unreachable once the membership gate lands | unreachable once membership + dedup-on-`h` + validated-`h` hold (§6) |
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

### 2.1 What R-B modifies — eight items, each to be ruled

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
   (`h_incl = current_height`); (b) **replace** the `h_close` gate (`:5186`)
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
   describes; `CHALLENGE_RESOLUTION_BLOCKS ≥ CHALLENGE_RESPONSE_BLOCKS`
   (`:183–185`) becomes load-bearing (item 5 depends on it). `λ` **must** be
   pinned to `CHALLENGES_PER_PAIR_PER_EPOCH` before any of this (Q4, §7.3).
7. **New daemon-side secret lifetime.** The producer of `h` retains the
   material to sign as witness for up to `W₂` blocks. Rust-owned,
   `ZeroizeOnDrop`, rules 35/36; wants a **stated restart policy**, because a
   daemon that loses it silently stops witnessing, and that shows up as `β`
   (non-observation), not as an error. §2.2 says *which* secret.
8. **Block weight — batching is the lever, ruled with its consequences.** At
   maturity (~97 draws/block) with one witness pk (1,996 B,
   `cryptonote_config.h:396`) + one hybrid sig (3,385 B, `:398`) **per
   record**: ~8.8 KB × 97 ≈ **850 KB/block** relayed, against a 300 KB
   penalty-free zone. **Batched per issuing block** — one witness tx carrying
   all of `h`'s records, one pk + sig for the batch: ~97 × 3.4 KB + 5.4 KB ≈
   **335 KB/block**. Permanent (kept) bytes: ~127 B × 97 ≈ 12 KB/block ≈
   3.2 GB/yr at 2-minute blocks either way. Prunable bytes still count toward
   block weight. Three consequences to rule: (a) the witness tx is a **single
   point of failure** for ~97 credits — its fee and submission path become
   availability-relevant in a way a per-record tx is not; (b) whether a batch
   is all-or-nothing under admission or admits its valid members; (c) the
   `tx_pool` class the batch tx belongs to (`serve_credit_only`,
   `blockchain.cpp:3480` in the credit-wire doc's numbering).

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

**This is Q8 (§10); the proposal's recommendation is the dedicated
non-output key, now made against `PL-D3` rather than against the defect.**
The shape of the commitment (transparent hash vs a `PL-D3a`-style
`pk ‖ blind` record) and whether the new tag gets a content rule at relay and
connect modelled on `check_pqc_leaf_entries` are Q12 and Q13.

---

## 3. `SO-D8a` — boundary arithmetic and the deadline gates, under R-B

**Proposed: the boundary rule is `E = epoch(h)` — the issuing block's epoch —
enforced by `SO-D9` (i) evaluated at `h`; the deadline is per-challenge,
`h < h_incl ≤ h + CHALLENGE_RESPONSE_BLOCKS`.** A draw at epoch-relative block
9,999 of `E` is answerable in any block up to epoch-relative 499 of `E+1`,
names `E`, and is counted for `E`. Nothing "straddles": the record's epoch is
a function of a validated height.

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

## 4. `SO-D8b` — dedup and the membership gate, under R-B

**Proposed: dedup widens to `(P, s, E, h)` as an exact-get; add `PC-D7`'s
membership gate against `assignment(h)`.**

- Dedup today (`blockchain.cpp:5156`): one serve-credit vin per `(P,s,E)`
  **per epoch** — pair-epoch-wide, `pass_count > 0`. Correct under the beacon
  (one challenge per pair-epoch). Under derived assignment with `λ = 3` draws
  per pair-epoch it would refuse the second and third honest passes, so it
  **must** widen. The widened key `(P,s,E,h)` exact-gets against the `PC-D4`
  ledger whose height field now means *issuing* block (§2.1 item 4); two
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
  window needs the urn's per-block draws retained for `W₂` blocks. See
  `SO-D8e`.

## 5. `SO-D8c` — emission gather, under R-B

**Proposed: the gather moves from `process_archival_epoch_close_at_height`
to the slash pass, alongside the settlement writer.** At `h_close(E)` the
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

## 6. `SO-D8d` — `passes > issued`

**Proposed: unreachable once membership (§4), dedup on `(P,s,E,h)` (§4) and
validated `h` (§2.1 item 3a) all hold — each `h` contributes at most one
record per pair, and only if `(P,s)` was drawn at `h`, so `passes ≤ issued`
by construction. Kept as a typed refusal that is FATAL at settlement, never
clamped.** `settle_epoch` (`attestation.rs:142–145`) already returns
`SettleError::MorePassesThanIssued`; `SettlementRow::settle`
(`settlement_row.rs:150`) refuses to compose a row; the writer maps that to a
FATAL (`db_lmdb.cpp` `set_archival_settlement` throws) rather than
`min(passes, issued)`: a clamp converts the collusion of §4 into **Served**,
silently, which is the one outcome the check exists to prevent. Rule 50's
"check that cannot fail" in its useful form — unreachable only while the
gates hold, and the FATAL is the alarm that they stopped holding.

## 7. `SO-D8e` — the `assign_epoch` FFI shape (the real item)

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

### 7.2 Proposed shape: a Rust-owned, in-memory, sequentially-fed urn with a `W₂` ring and checkpoints

**Rust owns the urn; nothing else does.** `ChallengeUrn` already is the
sequential form (`advance_block(prev_hash)` per block, `draws_done()`;
`challenge_assignment.rs:131–255`, `advance_block` at `:211`). The proposal is
a wrapper type in `shekyl-archival-retention`, no new crate:

```text
EpochAssignmentCache  (derived state; NEVER persisted — SO-D3 derive-don't-store)
  open(E, drawable_pairs_at_h_open)                        // fresh urn; λ = CHALLENGES_PER_PAIR_PER_EPOCH, not a parameter (Q4)
  advance(h, prev_hash) -> &[DrawablePair]                 // assignment(h); O(λ·pairs/SEB) per block; pushed onto the ring
  is_assigned(h, P, s) -> bool                             // admission gate; O(1) for any h in the trailing W₂ ring, refuse-not-guess outside it
  issued_histogram() -> impl Iterator<(DrawablePair, u32)> // writer input at settlement
  checkpoint() / rewind_to(h)                              // pop_block; pops the ring and the urn together
```

- **The `W₂` ring is R-B's addition.** Admission asks about *past* blocks, so
  the per-block draw sets must be retained: `W₂ × ~97 × 40 B ≈ 2 MB` at
  maturity. An `h` outside the ring is a **refusal**, never a replay on the
  admission path — the deadline gate (§3) has already refused anything older
  than `W₂`, so the ring's depth and the deadline are the same constant and
  must be read from the same place.
- **Precedent:** `ArchivalSealHashCache` — derived, in-memory, rebuilt from
  chain on restart, the pattern `SO-D3` named.
- **Reorg:** `pop_block` rewinds urn and ring to the popped height; a reorg
  deeper than the retained checkpoints replays from `h_open(E)` (bounded by
  one epoch = 1.09 s here). `SO-D6` already deletes settlement rows on
  revert; the cache follows the same height. §2.2's suffix argument means a
  popped `h_incl` never leaves a dangling reference to a live `h`.
- **Restart mid-epoch:** replay from `h_open(E)` on first use, rebuilding the
  ring for the trailing `W₂`. Same bound.
- **Retention (Q7, answered by construction):** the cache for `E` must live
  until the last record for `E` can be admitted — `h_close(E) + W₂` — and,
  if it is to feed the writer without a replay, until the slash pass at
  `h_close(E) + 10,000`. So two epochs' urns are resident by necessity for
  the first 500 blocks of each epoch; retaining through the slash deadline
  (zero replay at settlement) is the recommendation and costs one more
  epoch of a ~2 MB structure.
- **Ordering hazard, named:** the cache must be advanced with the *validated*
  predecessor's hash, never `prev_id` as supplied on an alt path — the same
  constraint `RF-D5` states for the attestation path's `prev_block_hash`.

**No FFI. SUPERSEDED 2026-09-16 (Q15).** *Superseded text: "one opaque
handle, five entry points … C++ marshals heights … In the redb store this
FFI does not exist."* The five-call adaptor was the C++ mirroring Q15
refused. `EpochAssignmentCache` is called from the Rust apply/pop path
only (`DAEMON_REDB_STORE.md` S-CHAIN-W / S-ARCH). It is designed for that
caller; nothing is listed on a deletion surface because nothing temporary
is written.

### 7.3 Inputs the shape needs that the tree does not yet supply

- **`drawable_pairs_at_h_open(E)`** — the set the urn is seeded with. The
  drawability relocation (`ARCHIVAL_CHALLENGE_MECHANISM.md` §4.1) fixes *when*
  it is evaluated; **no enumerator exists in the tree** (`rg -i drawable
  src/blockchain_db/` → none; Rust has only the `DrawablePair` type). Slice C
  work and a question (Q3): which table is the denominator, and is it frozen
  at `h_open(E)` or at the seal?
- **`lambda_target`** — a bare `u32` parameter at `challenge_assignment.rs:152`
  and `:264`. `CHALLENGES_PER_PAIR_PER_EPOCH = 3` exists (`constants.rs:27`)
  and is const-asserted against `SERVE_THRESHOLD_PASSES` (`attestation.rs:77,
  :82`), but **nothing connects it to the urn** — its only non-test consumers
  are in `shekyl-economics-sim`. The 972,000 figure assumes `λ = 3` by hand.
  **Must be pinned before any production caller** (Q4, confirmed by review):
  `EpochAssignmentCache::open` takes no `lambda_target` argument and reads the
  constant. Filed in `docs/FOLLOWUPS.md`.
- **The witness commitment** (§2.2) — a new coinbase `tx_extra` tag and its
  derivation domain. Neither exists.

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
| **Where the enumeration walk goes** | `shekyl-archival-retention::settlement::settle_epoch_rows(issued: impl Iterator<(DrawablePair,u32)>, passes: impl Fn(&DrawablePair)->u32) -> Vec<(ArchivalPairEpochKey, SettlementRow)>` — pure, testable, no storage. `issued` from `EpochAssignmentCache::issued_histogram()` (or one `assign_epoch` replay if not resident). The Rust apply/slash path (S-ARCH, DRS-E4) calls it and writes the rows **before** the fold, per `SO-D7`. No FFI; no C++ loop. |
| **How `issued` is obtained** | From the urn (§7), never from records (`SO-D1`: the forcing case has zero records). |
| **How `passes` is obtained** | The S-ARCH `archival_serve_credit_pass_count(P,s,E)` read — a per-pair-epoch count over the `PC-D4` widened key; **complete at `h_close(E) + W₂` and therefore at the slash pass** (`10,000 ≥ 500`). Same count, same table, Rust store. |
| **Where the emission gather goes** | Same hook, same pass (§5): `gather_archival_emission_epoch_snapshot` is called from the Rust slash pass after the writer, not from epoch-close. The invariant-2 joint pin moves with it. |
| **Admission changes (new `CEN-` rows in `shekyl-chain-rules`, not `blockchain.cpp`)** | Parse `h` (new kept field); refuse `h ≥ tip` or `h_incl − h > CHALLENGE_RESPONSE_BLOCKS`; `block_hash(h−1)` from `ChainView` for the leaf index; `settlement_epoch_at_height(h)` is `SO-D9` (i); `is_assigned(h, P, s)` against the in-process cache; witness check takes `h`'s coinbase witness tag bytes + the pruned witness pk/sig + the record preimage. Dedup: `archival_serve_credit_present(P,s,E,h)` exact-get replaces the `pass_count > 0` probe. The fire-height path is deleted; `ERR_CREDIT_DEADLINE` rebinds to the `W₂` window. Each refusal is a typed `InvalidBlock { rule: CenRow, … }` (CHAIN_RULES G3). Negative fixture per row (CHAIN_RULES §8). |
| **Witness key (pending Q8, Q12, Q13)** | `shekyl-crypto-pq`: `derive_witness_keypair(combined_ss)` under a new HKDF `info` (registry mechanism 2, review duty); commitment `cSHAKE256("shekyl/archival-witness-key-v1", canonical witness pk bytes)` (mechanism 1, count-pin +1; **not** `PL-D3`'s `pqc_key_scalar`, which is a leaf-domain scalar) written under the new coinbase `tx_extra` tag by the Rust miner-tx constructor. Content rule for the tag at relay and connect (exactly one entry, exactly 32 B, coinbase only) is a `CEN-` row modelled on #745's `check_pqc_leaf_entries`, if Q13 rules it — no FFI adapter. Node-side: a `ZeroizeOnDrop` ring of `W₂` witness seeds keyed by height, Rust-owned, with the restart policy Q10 rules. |
| **Batching (pending Q9)** | One `serve_credit` tx per issuing block per witness, carrying all of `h`'s records as vins; the witness pk + sig once, in the tx's prunable region, covering a preimage that binds every vin. Admission semantics per Q9(b). |
| **Cost** | One epoch replay per settled epoch if the cache is not resident (1.09 s here; Pi-4 owed), inside the slash pass, off the admission path. Admission: `O(1)` ring lookups + one hybrid verify per **batch** (or per record unbatched — 97 ML-DSA-65 verifies per block is the unbatched admission cost and is itself a reason to batch). Row writes: one per pair with `issued ≥ 1` (~324,000 × 51 B ≈ 16.5 MB per epoch at maturity, pruned at `MAX_CLAIM_AGE_W`). |
| **Reader precondition (`SO-D7`'s lag)** | Rows for `E` are absent until the slash pass at `h > h_slash_deadline(E)`; the window walk must **exclude** `E` until settled, not read absence as non-observation. Under R-B the *pass* table is also incomplete for `E` during `(h_close(E), h_close(E) + W₂]`, so the interim `> 0` presence read is wrong for one more reason during those 500 blocks. Stated as a reader constraint and tested (§10 item 5). |
| **Evidence plan (`ARCHIVAL_SETTLEMENT_WRITER.md` §10)** | Items 1, 2, 3, 6 unchanged. **Item 4 restated:** *a pass drawn at epoch-relative 9,999 and included at epoch-relative 400 of `E+1` is counted for `E`*. Its red edit — the **mutation that must turn the test red**, not the implementation — is to evaluate `SO-D9` at `h_incl` instead of `h`: that asserts the including block's epoch, `E+1`, and the vector must then be refused with `EPOCH_MISMATCH`. Green requires `settlement_epoch_at_height(h)` (§2.1 item 3, §3). **Item 5** as above. **New 7:** membership — a record citing an `h` at which `(P,s)` was not drawn is refused; red edit: delete the gate. **New 8:** collusion — records for one pair from a miner that won two *unassigned* heights settle **NonObservation/Missed**, never Served. **New 9:** deadline — a record with `h_incl − h = W₂ + 1` is refused, `= W₂` admits. **New 10:** witness — a record whose witness pk does not hash to `h`'s coinbase commitment is refused; a valid record re-signed under another block's witness key is refused. **New 11:** reorg — pop `h_incl`, reconnect on an alt suffix that keeps `h`: the record is gone, `h`'s draws are intact, re-inclusion admits. |
| **`CEN-L8` promotion path** | The census row's settlement clause names *"an unwired writer"* and puts settlement at epoch close; `SO-D7` puts it in the slash pass, and §5 now puts the emission gather there too. Path: (1) ruling lands here → (2) census row re-worded: two hooks per boundary stay (close + settlement), but the close hook no longer gathers emission → (3) writer + gather call sites land with the gates → (4) `DRS-P0f` re-reviews against the merged sha and records CHECKED-CONFORMANT. Not before step 3. |
| **What changes at the same cutover** | **Added:** `SO-D9` (i) at `h`; membership gate; deadline re-bound to `W₂`; witness authentication; `h` on the kept wire; new coinbase tag; dedup exact-get on `(P,s,E,h)`. **Deleted:** `challenge_fire_height` path, `ERR_FIRE_NOT_REACHED`, `ctx.block_hash_at_seal`; `archival_baseline_observed_at_epoch` as the interim `issued`; the `h_close` bound as a deadline. **Moved:** emission gather to the slash pass. **Superseded in-line (rule 23):** `PC-D2`; the `constants.rs:59` doc string becomes true and stays. |

**Sequencing against DRS — SUPERSEDED 2026-09-16 (Q15).** *Superseded
text: "none of the above blocks on redb, and none of it thickens the C++
beyond marshaling. If redb's `apply_block` lands first, the FFI half is
simply never written."* DRS-D12 turned the if into the ruling. Two
preconditions, both named, both falsifiable:

1. **`shekyl-chain-rules` is the live connect validator** — `ChainValid`
   minted only by that crate, no C++-verdict shim (DRS-D12 (ii)). E6
   increment 1 (scaffold) landed 2026-09-15; increments 2+ port the 141
   surface-free rows. SO's new rows ride an E6 increment of their own
   (or the S-ARCH-bound slice of E4 — CEN-L8 already sits on E4
   S-ARCH). Falsify: `ChainValid` constructed from a C++ return code.
2. **S-ARCH (DRS-E4) has ported the settlement write path** — today's
   `set_archival_settlement` four-tuple is still LMDB-only production
   (known-unwired, `DAEMON_REDB_STORE.md` §3.5); S-ARCH is priority 7 of
   9 and gated on the P0b journal audit. The writer's call site is a
   store write, so it waits on that surface. Falsify: a production
   caller of the settlement write on the Rust apply/slash path.

Until both, the LMDB daemon's beacon / `h_close` / seal gates stay, and
Slice C is not authorized. The settlement methods are **not** on the
S-ARCH method list today (the table was born after that census); they
join that row when E4 is scoped — DRS inventory, not an SO family.

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
| `SO-D8` (parent) | Premise **stands** (§1). Shape **R-B** adopted: the record names and validates its issuing block `h`; `E = epoch(h)`; deadline `h_incl ≤ h + W₂`. `PC-D2` reversed (F4). | **DIRECTION RATIFIED 2026-09-13**; items §2.1 1–8 to be ruled individually |
| `SO-D9` (standalone) | `ERR_EPOCH_MISMATCH` is a tautology. **(i)**: the record's epoch equals `settlement_epoch_at_height(h)` of the validated issuing block. Lands as a `shekyl-chain-rules` row with the R-B cutover (Q15); not a C++ one-liner. FOLLOWUPS row carries it. | **RULED 2026-09-13 — (i)**; site **re-homed 2026-09-16 (Q15)** |
| `SO-D8a` | Boundary rule `E = epoch(h)`; `ERR_FIRE_NOT_REACHED` dies; **`h_close` deadline replaced** by the per-challenge `W₂` bound in both twins (the first cut's "keep untouched" was under R-A). | **PROPOSED** |
| `SO-D8b` | Dedup **widens** to `(P,s,E,h)` exact-get (resolves — `PC-D7`'s deferred half discharges); add `PC-D7`'s membership gate against `assignment(h)`. | **PROPOSED** |
| `SO-D8c` | Emission gather **moves to the slash pass** — `SO-D7` applied to its second consumer; invariant-2 joint pin moves with it. Presence-vs-absolute-2 recorded, not opened. | **PROPOSED** |
| `SO-D8d` | `passes ≤ issued` by construction under membership + dedup-on-`h` + validated `h`; FATAL at settlement, never clamped. | **PROPOSED** |
| `SO-D8e` | `EpochAssignmentCache` with a `W₂` ring: Rust-owned, in-memory, sequential, checkpointed, never persisted; `λ` from the constant (Q4); retained through the slash deadline (Q7); called from the Rust apply/pop path only. The 5-call C++ FFI adaptor is **SUPERSEDED** (Q15). | **PROPOSED** |
| `W₂` (Q2) | Under R-B `CHALLENGE_RESPONSE_BLOCKS` **is** the per-challenge deadline and the const-assert coupling it to `CHALLENGE_RESOLUTION_BLOCKS` is load-bearing (§5 depends on it). FOLLOWUPS row re-worded from "no referent" to "referent pending the cutover". | **RESOLVED by R-B** |
| Witness key (Q8) | **Dedicated non-output hybrid key** derived from the coinbase `combined_ss` under a registered domain, committed (transparent cSHAKE256, own customization) under a new coinbase `tx_extra` tag; pk + sig pruned. The coinbase output's own per-output key is **ruled out by `PL-D3`'s premise** — the key is published once, at spend; a witness reveal would be the second publication (§2.2). Commitment shape and tag content rule are Q12/Q13. | **PROPOSED — Rick's** |
| Batching (Q9) | One witness tx per issuing block; consequences (a)–(c) of §2.1 item 8 to be ruled. | **PROPOSED — Rick's** |
| Slice A1 (Q6) | **Keep**, per review, on grounds narrower than §12 gave. | **ANSWERED — keep** |
| F3 | First cut's F1 row 1 cited the attestation path for the vin's binding; corrected at source. | **CORRECTED** |
| F4 | `PC-D2` ↔ mechanism §2 contradiction; `PC-D2`'s herd premise inverted; reversed by R-B. In-line supersession at `PC-D2` owed with the ruling PR. | **RECORDED** |
| **F5** → `PL-D1` | **Every FCMP++ spend is linkable to its output by the public 4th leaf scalar.** Tree-wide, pre-genesis, priority-2. Opened by Rick as the `PL-` round 2026-09-13/14; **CLOSED by `PL-D3`** (hiding Pedersen commitment opened in-circuit) in PR #745, **merged 2026-09-14**; `PL-D4` (hash mechanism) at V4. This proposal's FOLLOWUPS line withdrawn 2026-09-14 per `PL` §12 ruling 11. | **CLOSED by #745 (merged)** |
| Sweep on ruling | `constants.rs:59` W₂ doc (becomes true — keep); `ARCHIVAL_SETTLEMENT_WRITER.md` §6/§12/§13 and the `IMPLEMENTATION_INDEX.md` SO-row `SO-D7` lag sentence (become true — re-date); `PC-D2` and its citations (`ARCHIVAL_PER_CHALLENGE_RECORD.md`, `TJ` `:819–822`) marked SUPERSEDED in-line; `FCMP_PLUS_PLUS.md:102–104,:121–122`, `POST_QUANTUM_CRYPTOGRAPHY.md:735–737`, `MERKLE_TREE.md:235` — **F5's sweep, DONE by #745 at source** (`PL` §11; the `REWARD_EMISSION_LEG.md` §7.3 tripwire marked FIRED there too). | owed with the ruling PRs (`PL` half done) |

### 9.1 Figures flagged for re-derivation

| Figure | Source | Status 2026-09-13 |
|---|---|---|
| ~972,000 assignments / epoch | `3 × 324,000`, `challenge_assignment.rs:534`, asserted at `:555` | **Holds** as `λ·pairs`; `λ = 3` is a test parameter, not a pinned constant (Q4). Cost **measured** 1.09 s release on this host; Pi-4 owed. |
| ~97 draws / block at maturity | `972,000 / 10,000` | Arithmetic; the per-block witness load and the ring size derive from it. |
| 72 % unobservable at `k_cap = 30` | `ARCHIVAL_CHALLENGE_MECHANISM.md:1185` histogram `{0: 35 %, 1: 37 %, 2: 28 %}` | **Not re-derived** — doc-only figure, no code artifact. Under R-B the capped-regime mechanics are unchanged (the window changes when a draw is answered, not how many are drawn). Flagged *unverifiable at source*. |
| ~3,411 B record; 5,107 B pre-`RF-D6` | `ARCHIVAL_RESPONSE_FORMAT.md:974`, `:845` | Not re-derived; R-B adds `h` (≤ 10 B kept) and the witness material (1,996 + 3,385 B pruned, per record or per batch). |
| 1,996 / 3,385 B hybrid key / sig | `cryptonote_config.h:396,:398` | **Grounded.** |
| 850 KB / 335 KB per block | §2.1 item 8 | Arithmetic on the grounded figures; the 300 KB penalty-free zone is quoted from Rick's message and **not re-grounded here** — owed. |

### 9.2 Wargames under R-B

| Scenario | What happens | What stops it |
|---|---|---|
| **Adaptive-selection archiver** — `P` serves only when it can predict it is assigned | `assignment(h)` is public at `h−1`; `P` can predict *that* it is drawn. But the witness is `h`'s winner, unknown until mined, who fetches within `W₂`; `P` refusing everyone but a colluding pool earns non-observation from honest winners, which under 2-of-3 with `λ = 3` is **Missed** unless the colluder wins ≥ 2 of the 3 assigned blocks. | Membership gate + witness authentication + `PC-D3` leaf drawn at `h−1`; residual priced by the quadratic. |
| **Forged issuing block** — record cites an `h` at which the pair was not drawn, or which the includer did not produce | (a) `h` outside `[h_incl − W₂, h_incl)` → deadline refusal; (b) `(P,s) ∉ assignment(h)` → membership refusal; (c) `h` real and assigned but signer is not `h`'s producer → witness hash-compare against `h`'s coinbase commitment fails. | §2.1 item 3 (a), (d), (e). |
| **Boundary-straddler** — draw at epoch-relative 9,999 of `E` | Answerable in blocks `[10,000, 10,499)` of the chain — epoch-relative `[0, 499)` of `E+1` — names `E` (`epoch(h) = E`), counted for `E`, present in the table by `h_close(E) + 500`, read by the writer and the emission gather at `h_close(E) + 10,000`. | `SO-D9` (i) at `h`; §5's move; `CHALLENGE_RESOLUTION_BLOCKS ≥ CHALLENGE_RESPONSE_BLOCKS`. |
| **Reorg across `h_close(E)`, or across `h`** | Suffix property (§2.2): no connected record can reference a removed `h`. Alt branch's blocks carry their own records (leaf index bound to their own `h−1`); losing branch leaves no residue. Settlement rows for `E`, if written, are deleted by `revert_archival_slashes_at_height` and recomputed on reconnect (`SO-D6`); cache and ring rewind together. | `SO-D6` + §7.2. **Unread, named:** the pop order in `blockchain_db.cpp:748–749` reverts slashes before epoch-close; confirm the cache rewind is sequenced before either. |
| **Witness key loss** — producer of `h` restarts and loses the witness seed | Draws at `h` fall to non-observation; nothing errors. Shows up as `β`. | Q10's restart policy; at minimum a metric. Not a consensus concern; an availability one. |
| **Batch as single point of failure** (Q9) | One witness tx carries ~97 credits; if it is underfunded, malformed, or unrelayed, all ~97 draws at `h` are non-observation. | Q9 (a)–(c). |
| **Under-issuance regime** (`k_cap` binding) | Pairs with `issued ≤ 1` settle NonObservation with a row (`SO-D1`), so degradation is measured, not silent. Unchanged by R-B. | `SO-D1`/`SO-D2`'s `issued` byte. |
| **`PL-D3` interaction** (was "F5 interaction") | `PL-D3` (#745) holds because the per-output key is published once, at spend. A witness scheme keyed on a spendable output's pk publishes it a second time, labelled with `h`; the later spend is linked by byte equality — `PL-D3` void on every witnessing coinbase. Witness key derived under its own HKDF `info` is independent of the sibling per-output key, `r` and `r_h`. | Q8: the non-output witness key; Q12/Q13 for its commitment. |

---

## 10. Questions for Rick

Seven were posed in the first cut; four answered in the 2026-09-13 review,
`SO-D9` ruled, and R-B ratified the same day, which resolves 1, 2 and 7. Four
new ones arise from R-B; Q11 is resolved by the `PL-` round and #745; Q12–Q13
were opened in the 2026-09-14 reconciliation; Q14 was opened by #747 review
and is resolved by Q15 (2026-09-16). **Open: 3, 8, 9, 10, 12, 13.**

1. **RATIFIED — R-B.** The herd is R-A's, not R-B's (F4). Recorded §2.
2. **RESOLVED by 1.** `CHALLENGE_RESPONSE_BLOCKS` becomes the per-challenge
   deadline; the const-assert becomes load-bearing.
3. **OPEN — (Slice C input)** What is the drawable set at `h_open(E)`, and
   from which table is it enumerated? No enumerator exists.
4. **ANSWERED — unpinned, must be pinned before any production caller.**
   `lambda_target` is a bare `u32` at `challenge_assignment.rs:152` / `:264`.
   §7.2's `open()` drops the parameter and reads the constant. Filed.
5. **ANSWERED, then RULED.** `ERR_CREDIT_DEADLINE`'s disposition changed with
   R-B — it is **re-bound** to the `W₂` window, not kept as `h_close` (§3).
   The vacuous check was `ERR_EPOCH_MISMATCH` (`SO-D9`), ruled (i).
6. **ANSWERED — keep A1.**
7. **RESOLVED by 1.** The cache must retain `≥ W₂` of per-block draws for
   admission regardless; retaining through the slash deadline is one more
   epoch of ~2 MB and removes the settlement replay. Recommendation: retain.
8. **OPEN — (Witness key; `PL-D3` rules one option out)** Dedicated
   non-output hybrid key derived from the coinbase `combined_ss` under a
   registered domain, committed under a new coinbase `tx_extra` tag
   (proposal's recommendation, §2.2); or a dedicated never-spent coinbase
   output (your dodge — works, costs a leaf + 64-B `0x07` entry + KEM
   ciphertext per block, all scan-verified for nothing); or the coinbase
   output's own per-output key (**ruled out** — `PL-D3` holds because that
   key is published once, at spend; a witness reveal is the second
   publication and voids the fix on every witnessing coinbase).
9. **OPEN — (Batching)** One witness tx per issuing block: (a) fee source and
   submission path given it is a single point of failure for ~97 credits;
   (b) all-or-nothing admission or admit-valid-members; (c) its tx-pool
   class.
10. **OPEN — (Secret lifetime)** Restart policy for the witness seed ring:
    persist encrypted for `W₂` blocks (a secret at rest, rule 35), or accept
    loss as `β` with a metric. Rust-owned either way.
11. **RESOLVED 2026-09-14 — (F5)** You opened it as the `PL-` round the
    same day; `PL-D1` is the defect, `PL-D3` the fix, ratified and landing in
    #745; `PL-D4` at V4. It gates nothing in `SO-D8` beyond #745 merging
    first (§8, "Sequencing against `PL-D3`"). This proposal's FOLLOWUPS line
    is withdrawn; Q8's recommendation is re-made against `PL-D3`.
12. **OPEN — (Witness commitment shape, new with #745)** The coinbase tag
    commits the witness key as a **transparent** 32-B cSHAKE256 read of the
    canonical key bytes under `shekyl/archival-witness-key-v1` (proposal's
    recommendation: the role is public by construction and the key is
    revealed within `W₂`, so hiding buys nothing, and a hash over the key
    bytes is what a lattice-only verifier can still check at V4). The
    alternative is `PL-D3a`'s record shape, `cSHAKE256(pk ‖ blind)`, which
    hides the key until reveal at the cost of one more HKDF child and
    carrying the blind in the record's pruned half — buying only that an
    observer cannot test a *guessed* witness key against a block before the
    reveal, which no adversary model in §9.1 needs. Rule either way; the
    proposal says transparent.
13. **OPEN — (Tag content rule, new with #745)** #745 makes `0x07` shape a
    consensus rule at relay and connect (`check_pqc_leaf_entries`, FFI code
    10). The new coinbase witness tag should get the same treatment —
    exactly one entry, exactly 32 B, coinbase only — through the same FFI
    adapter, so a malformed or absent commitment is refused at admission
    rather than discovered when the first record citing `h` arrives and
    cannot be verified. Proposal: yes, same PR as the tag. Cost: one CEN
    row in `shekyl-chain-rules` (Q15: no adapter, no C++).
14. **OPEN — (`SO-D9` (i) sequencing, surfaced by review of #747)** With the
    two pre-FFI bounds in place (§1, "Ordering"), (i) built alone changes the
    verdict on exactly one block per epoch: a record for `E` in block
    `(E+1)·N` goes from admitted to refused, and R-B's `epoch(h)` operand
    admits it again. Rule one of: (a) land (i) **with** the R-B cutover, as
    the same site (`:5304`) with its final operand — no interim flip, and the
    isolated verifier test covers the check either way; or (b) land (i) now
    on `current_height`, accept the one-block refusal as the interim rule
    (it is the stricter reading), and re-target the operand in the cutover.
    Proposal: **(a)** — the check's reason to exist is the post-cutover path,
    and (b) writes a consensus change that the next PR reverses.
    **RULED 2026-09-16 by Q15 as (a), stronger:** not merely "with the
    cutover" but *in* `shekyl-chain-rules`, never as a C++ one-liner on
    the LMDB path. The one-block flip does not ship.
15. **RULED 2026-09-16 — (Placement)** Wait until SO can be written
    directly in Rust; no C++ mirroring. Admission gates are new `CEN-`
    rows in `shekyl-chain-rules` (E6 increment; ids at Slice C). Writer
    call site waits on S-ARCH (DRS-E4) porting the settlement table.
    Pre-cutover LMDB daemon keeps today's beacon / `h_close` / seal
    gates. Falsify by `shekyl-chain-rules` being the live connect
    validator (`ChainValid` without a C++-verdict shim) **and** a
    production settlement write on the Rust apply/slash path. Until
    both, Slice C is not authorized. Subsumes Q14.
