# C2-R3 — Timestamps design round: MTP boundary, bootstrap carve-out, alt-path FTL

**Status:** **RATIFIED 2026-09-01 (Rick)** — all three rulings signed as
proposed (§8); implementation lands in this round's PR. First design round of
the C2 program ([`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md) §10
batch R3). Ratification review independently re-derived every load-bearing
claim against `dev @ 30cd547e2`; no factual corrections. The §5.1
genesis-mint-timestamp flag was ruled a FOLLOWUPS row, not this PR's scope.
**Pinned sha:** `30cd547e2e9146bd30d7313e644246a9794b57d3` (`dev` tip,
2026-09-01). Every `file:line` in this doc was re-located at this pin; where a
prior citation drifted, both numbers are recorded.
**Identifier family:** `C2-R3-Q1…Q3` (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 this PR). Census rows
in scope: CEN-C2 (Q1), CEN-C3 (Q2), CEN-C1's alt-FTL note (Q3).
**Authority chain:** census §10 R3 + rows CEN-C1/C2/C3 (CEN-C2 adjudicated at
the tree by C1 steering — built on, not re-derived);
[`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) §4–§5; pinned LWMA sources
[`refs/zawy12_issue_3_lwma1.md`](refs/zawy12_issue_3_lwma1.md) /
[`refs/zawy12_issue_24_history.md`](refs/zawy12_issue_24_history.md); rules
00 / 30 / 50 / 60.

**Scope fence (restated from the dispatch):** reorg / checkpoint / fork-choice
questions beyond Q3's FTL placement are R1 material (20 rows). This round does
not open them.

---

## 1. Ground at the pin

The rule under examination is one rule with five surfaces. Two of the five
were not in the census row and were found by this round's re-grounding pass.

| # | Surface | Where (at `30cd547e2`) | Behavior today |
| --- | --- | --- | --- |
| 1 | Ratified spec | [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) §5.5 :1511–:1514 | "must be **strictly greater** than the median … Already implemented in the inherited block-header validator; preserved unchanged" — the premise ("preserved unchanged") is refuted at surface 2; the census carries this as class `ratified-premise-refuted` |
| 2 | Live C++ validator | `src/cryptonote_core/blockchain.cpp:5519` (vector overload body 5514–5527) | `if (b.timestamp < median_ts) return false` — **non-strict**: equality accepted. Median via `epee::misc_utils::median` |
| 3 | Unwired Rust predicate | `rust/shekyl-difficulty/src/timestamp.rs:64` (`is_above_mtp`) | `incoming > median` — **strict**, spec-conformant, **zero production callers** |
| 4 | **Miner-template floor (Jagerman bump) — found this round** | `blockchain.cpp:1948–1954` (the spec's §5.5 cite of :1650–1656 has drifted; same code) | `if (!check_block_timestamp(b, median_ts)) b.timestamp = median_ts;` — sets the template timestamp **to** the median. Self-consistent only under the non-strict boundary; under strict it mints a template the node itself rejects whenever `time(NULL) ≤ median` |
| 5 | **Alt-path window shape — found this round** | `build_alt_chain` `:2158–2202` pushes **every** alt-chain timestamp (no cap); `complete_timestamps_vector` `:2133–2152` only tops **up** to 11; median at `:2307` runs over the result | For alt chains longer than 11 blocks the median is computed over the **whole alt chain** (window > 11); for even-length windows `epee::misc_utils::median` **averages the two middle elements** (`contrib/epee/include/misc_language.h:64–67`) — a second, undocumented median definition on the alt path. Near-genesis alt forks (fork height < 11) also produce short, possibly even windows |

Supporting facts, verified at the pin:

- **epee median, odd window:** sorts, returns `v[n/2]` (`misc_language.h:58–63`).
  For 11 elements that is sorted index 5 — the census's assumed-never-specified
  semantics, now independently confirmed and written into the ruled sentence.
- **Main-path window:** exactly the 11 timestamps at heights `h−11 … h−1`
  (`blockchain.cpp:5552–5560`). Bootstrap carve-out: `h < 11 → return true`
  (`:5545–5550`), *after* the FTL check (`:5538–5543`) — FTL runs from block 1
  on the main path; the median check does not.
- **Alt admission runs no FTL:** the alt path calls only the vector overload
  (`:2307`); the FTL clause lives only in the non-vector overload (`:5538`).
  This is CEN-C1's recorded gap (FOLLOWUPS :185).
- **Timestamp rejection never blacklists:** the only `add_block_as_invalid`
  caller is the bad-tx-inputs arm of block connect (`:6058`). A block rejected
  for a timestamp is dropped, not poisoned — it can be re-received and accepted
  later. Q3's add-FTL option therefore cannot wedge a briefly-future block.
- **Difficulty is not timestamp-driven inside the carve-out (Q2's anchor
  fact), verified:** `lwma1_next` short-circuits to `GENESIS_DIFFICULTY`
  (=100) for `chain_height < N` (=90) — `rust/shekyl-difficulty/src/lwma1.rs:70–72`,
  reached from C++ via `shekyl_difficulty_lwma1_next` (`blockchain.cpp:193`,
  `:1169`). CEN-D4 (bucket 1) says the same. The 11-block carve-out sits
  entirely inside the 90-block constant-difficulty window.
- **Non-consensus neighbor, explicitly out of scope:** `get_adjusted_time`
  (`:5480–5511`) computes an 11-window median for unlock-time leeway and RPC
  display only. Not a read site of this rule; unchanged by this round.

---

## 2. What the LWMA-1 source actually requires of MTP (fetch-the-paper)

Read at the repo's pinned captures (SHA-256-anchored per `DAA_LWMA1.md` §3),
not from memory:

- The **entire** MTP requirement in the LWMA-1 reference is one config line:
  `// BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = 11; // aka "MTP"`
  ([`refs/zawy12_issue_3_lwma1.md`](refs/zawy12_issue_3_lwma1.md) :66). It
  names the inherited CryptoNote check and sets its **window**; it says nothing
  about the comparison boundary. (The CN check it configures is the non-strict
  one — a fact about the inherited code, not an argument; rule 60.)
- The algorithm **does not assume strict monotonicity past the median**. The
  reference body sanitizes non-increasing timestamps internally
  (`:95–101`: `if (timestamps[i] > previous_timestamp) … else previous+1`), and
  Shekyl's ratified variant does the same job via running-max + signed
  solvetime + symmetric `±6T` clamp (`DAA_LWMA1.md` §5.3 steps 2–3; a
  window-equal timestamp contributes a clamped solvetime of 0).
- The manipulation analysis
  ([`refs/zawy12_issue_24_history.md`](refs/zawy12_issue_24_history.md))
  credits MTP's defensive value to the **window size** ("a certain theoretical
  malicious attack is now stopped by using MTP=11 instead of 60", item 10) and
  places out-of-sequence-timestamp protection **inside the algorithm or
  stricter-than-MTP outside it** (item 14 — Shekyl adopted the inside form).
  Item 7 (Jagerman patch) concerns template liveness, not the boundary.

**Conclusion (Q1 input):** LWMA-1's security argument requires the median
*floor* and FTL; it is **indifferent to the `>` vs `≥` boundary**. Neither
pinned source distinguishes them anywhere. The boundary choice is therefore
free on the security axis and is decided on commitment 3 grounds (§4).

---

## 3. Boundary frequency and the invalidation stake (the measurement)

**Analytic expectation.** Equality (`candidate == median₁₁`) requires the new
timestamp to equal the median of its 11 predecessors — under honest wall-clock
mining at `T = 120 s` the median trails the tip by roughly 600–700 s, so
honest equality is effectively impossible. Equality arises under burst mining
(many blocks per second against a near-constant window) and fixed-clock
miners — stressnet conditions, not mainnet ones.

**The invalidation stake is resolved by circumstance, not by the count.** The
existing stressnet chain is condemned twice over, independent of this ruling:

1. Its genesis is the pre-remint `7cbb8529…` (superseded by commit
   `b56369fc8`, "genesis: remint the tx key onto payment identity"); current
   builds carry `ac2c43bd…` and refuse the chain at `NOTIFY_REQUEST_CHAIN`
   (observed live from this box, 2026-09-01: all estate peers dropped with
   "genesis block mismatch").
2. Its datadirs are pre-V11 schema; current builds refuse them at startup with
   "no pre-genesis migration path exists. Delete the data directory and
   resync" (observed at startup against the local stale datadir, 2026-09-01).

The estate rebuild off fresh datadirs was ruled by Rick on 2026-08-26 (LMDB
V10 bump record). **A strict ruling therefore invalidates no chain that has a
future**; the dispatch's "regenesis/resync is the disposition" is subsumed by
the already-required rebuild.

**Empirical count: zero, definitively — the chain is empty.** A
matching-genesis daemon (scratch build at `c1093c533`, the commit preceding
the remint) was synced against the estate over P2P on 2026-09-01. It held four
connections; the three peers reporting a height (`134.199.166.22` seedaus,
`139.162.71.114` seedjp, `45.76.171.128`) **all report height 1 — genesis
only**.
The "existing stressnet chain" holds no non-genesis blocks at all: equality
count = 0, blocks invalidated by a strict ruling = 0. The planned scan
(for each `h ≥ 11`, compare `ts(h)` against sorted-index-5 of
`ts(h−11 … h−1)`) had an empty domain; it remains the recipe for the rebuilt
estate once it has history.

---

## 4. Q1 — the MTP boundary (CEN-C2)

The ruling is on the merits; no artifact wins by default. In particular the
spec's §5.5 "strictly greater" is **not** treated as a standing decision —
its stated premise was refuted, so the boundary is re-derived from zero here
and §5.5 is re-ratified (or corrected) on fresh ground.

### 4.1 Wargame

| Axis | **Strict `>` (proposed)** | Non-strict `≥` (live) |
| --- | --- | --- |
| DAA security (commitment 1) | Indifferent — §2. The four-mechanism defense surface (MTP + FTL + clamp + running-max) is unchanged by the boundary | Indifferent — same |
| Chain-time progress (commitment 3) | **Unconditional invariant: the 11-window median strictly increases over time; chain time cannot stall.** Every present and future consumer of block time (unlock windows, staking epochs, `get_adjusted_time`, any V3.x/V4 time-based rule over the ~30-year mining era) inherits guaranteed progress by construction | Frozen chain time is *representable*: a majority miner can hold `ts == median` indefinitely without violating any rule. It is economically self-punishing (all-zero clamped solvetimes floor `L` at `N·N·T/20`, multiplying difficulty ≈ ×9.9 per window — `DAA_LWMA1.md` §5.3 steps 5–7), but the guarantee is economic, not structural |
| Honest-miner cost | Zero — honest timestamps sit ~600–700 s above the median (§3). Burst mining drifts ≤ 1 s per 6 blocks ahead, absorbed by FTL = 540 s | Zero |
| Template liveness | Requires the Jagerman floor to become `median + 1` (surface 4, §4.2b). With it, identical liveness | As-is |
| Chain invalidation | Nil — the only chain with equality blocks is condemned regardless (§3) | Nil |
| Ecosystem semantics | Matches Bitcoin's well-studied strict MTP (`GetBlockTime() > GetMedianTimePast()`); precedent noted, **not** authority (rule 60) | Matches inherited CryptoNote; precedent, not authority (rule 60) |
| Rule statement | One clean strict lower bound; the two spec-side legs (§5.5, `is_above_mtp`) already say it | Requires editing both spec legs to the inherited behavior |
| Implementation cost | Flip one C++ comparison; `median + 1` template floor; shared vectors | Edit spec §5.5 + Rust predicate (rename `is_above_mtp` or invert); shared vectors |

**Proposed ruling Q1: strict.** Binding commitment: **#3 — the system must
outlast the team.** The security commitment (#1) is named neutral (§2: the
DAA's manipulation analysis is boundary-indifferent), privacy (#2) is not in
play, and #3 arbitrates: the strict boundary gives every future time consumer
a structural progress invariant instead of an economic argument, at zero cost
to honest participants and zero surviving-chain invalidation.

### 4.2 Named sub-decisions inside Q1 (ratified as part of the sentence, not left to the PR)

**(a) The alt-path window is truncated to exactly the 11 timestamps
immediately preceding the candidate.** Today the alt median runs over the
whole alt chain (surface 5) — a second window definition, with even-length
averaging, that no document ever specified. Under the ruled sentence
(window = 11, median = sorted index 5) the alt path selects the **newest 11**
of `main[..fork) ++ alt`. This is a real behavior change for alt chains
longer than 11 blocks (the old whole-chain median trails lower, so the ruled
form is generally *stricter* there) and it is CEN-C2's own cited surface
(`:2307` / `:2133`), not R1 scope.

**(b) The miner-template floor becomes `median + 1`** (surface 4). This is
the liveness complement of strict — without it a node whose clock sits at or
below the median mints self-rejecting templates. One clause of the ruled
rule: *templates floor their timestamp at the smallest consensus-valid
value.*

**(c) The median is specified, not inherited:** window = 11, sorted
ascending, median = element index 5 (0-based). `epee::misc_utils::median`'s
odd-window arm happens to compute this (§1); the sentence stands on its own
so the rewrite implements arithmetic, not a library.

### 4.3 The ruled sentence (proposed, composing Q1 + Q2 + Q3)

> A candidate block's timestamp `T` is consensus-valid iff
> **(FTL)** `T ≤ local_clock + 540 s`, checked wherever the block enters a
> store (main connect **and** alt admission), and
> **(MTP)** `T > M`, where `M` is element index 5 (0-based) of the sorted
> window of the 11 timestamps immediately preceding the candidate on its own
> chain (alt suffix + main prefix on the alt path), the window right-padded
> with the genesis timestamp when fewer than 11 predecessors exist.
> Miner templates floor their timestamp at `M + 1`; when no timestamp
> satisfies both bounds — `M` at the local FTL deadline, an at-most-one-
> second self-healing state (every stored timestamp passed FTL at its own
> admission, so `M ≤ now + 540` always) — template creation refuses
> loudly rather than minting a template the node itself rejects.
> The rule governs blocks at height ≥ 1: block 0 has no predecessors and
> is pinned by the compiled genesis identity, not by this rule (its one
> validator-side arrival is `Blockchain::init`'s locally constructed
> genesis add on an empty store).

---

## 5. Q2 — the bootstrap carve-out (CEN-C3)

Today: `h < 11 → return true` (`:5545`) — FTL only, no median check, for the
first 10 post-genesis blocks. Two candidate rulings.

### 5.1 Wargame

| Axis | **Replace: genesis-timestamp padding (proposed)** | Keep with recorded rationale |
| --- | --- | --- |
| Hazard closed | **Small, honestly stated:** Shekyl's genesis header timestamp is `0` (`rust/shekyl-genesis-tool/src/builder.rs:181`), so a `0`-padded window has median 0 and strict `>` admits `ts = 1` — padding closes only `ts = 0` itself at first; past-dating in blocks 1–10 remains admissible until real timestamps refill the window (as today). Either way the damage is bounded: difficulty is the constant 100 until height 90 (§1, verified), the `±6T` clamp + running-max bound any absurd timestamp to one clamped solvetime, and the median is majority-robust | Hazard stays, same bounds |
| Rule shape | **The carve-out branch is deleted; one sentence covers every height from block 1** (§4.3). The rewrite implements no bootstrap special case | The rewrite carries a ratified two-branch rule forever |
| Composition (the decisive row) | The same padding fixes the **alt path's near-genesis short/even windows** (surface 5's second half) for free, and deleting the `h < 11` early-return lets one shared function own FTL + median for **both** paths — main and alt become the same call | The alt near-genesis even-window averaging accident needs its own separate fix or its own ratified shrug |
| Launch semantics | With today's `genesis_ts = 0`, none — block 1 accepts any `ts ≥ 1`, materially the same as keep. **If** genesis ever carries a real mint timestamp, padding upgrades for free: the chain then cannot start "before" its own genesis time (Bitcoin's MTP property). **Flag for ratification, one line, not R3 scope:** should Shekyl's genesis header carry a real timestamp? That is a genesis-mint decision (geblock + pinned block ids), recorded here as a question only | Block 1 accepts any `ts ≤ now + 540` |
| Cost | ~10 lines of window-assembly C++ (pad, don't branch) + vectors. Consensus behavior changes for exactly the first 10 blocks of any chain, ever | Zero code; a rationale paragraph moves the row to bucket 2 honestly |

**Proposed ruling Q2: replace — pad the window to 11 with the genesis
timestamp.** Binding commitment: **#3.** Keep-with-rationale is legitimate
(the hazard really is bounded — that boundedness is recorded above either
way), but the composition row decides it: padding is what collapses the
whole rule — both paths, all heights — into §4.3's single sentence, and it
dissolves the alt-path short-window accident this round would otherwise have
to rule separately. The padding concept costs one clause ("right-padded with
the genesis timestamp") in a rule the rewrite must state anyway.

---

## 6. Q3 — FTL at alt admission (CEN-C1 note)

Today a `now + 541` block is refused at main connect but admitted to the alt
store; FTL is re-applied only at promotion (by which time the block may no
longer be future). Two candidate rulings: add FTL at alt admission, or
ratify promotion-time-only with a bounded-hazard argument.

### 6.1 The hazard, precisely (and no further)

Fork-choice theft is **not** the hazard: alt PoW is checked at alt difficulty
at admission (CEN-K4), and cumulative difficulty sums the difficulties the
attacker actually mined at — future-dating *lowers* alt difficulty, so each
fabricated block contributes proportionally less; overtaking main still costs
main-equivalent total work. The hazard is **cheap alt-store spam**: without a
future-time bound, an attacker can advance fabricated timestamps `+6T` per
block indefinitely, saturating LWMA-1's solvetime clamp on every step, which
drives the alt-difficulty output geometrically toward its floor (all-clamped
window ⇒ `L = 6T·ΣI = 3·T·N·(N+1)` ⇒ `next_D ≈ avg_D·99/600` per §5.3 step 7
— compounding per block as the cheap blocks refill their own window). The
result is an unbounded stream of *valid-PoW-at-trivial-difficulty* alt blocks
that every node must verify (RandomX) and store. With FTL at admission the
fabricated-timestamp budget is capped at `real_elapsed + 540 s`, so sustained
clamp-saturation is impossible and alt difficulty stays coupled to real time.

The anchors/conscription design bounds *eclipse* — who can occupy your
outbound slots — not the cost of paid spam offered over any one honest
connection; it is not a substitute bound, and no other bound exists at the
pin (compiled checkpoints are genesis-only pre-launch). Fork-choice semantics
beyond this paragraph are R1's.

### 6.2 Wargame

| Axis | **Add FTL at alt admission (proposed)** | Promotion-time-only, ratified |
| --- | --- | --- |
| Spam bound | Fabrication budget ≤ `real_elapsed + 540 s`; the §6.1 decay attack is structurally impossible | Requires a bound that does not exist at the pin (§6.1); the ruling would ratify an unbounded per-peer verify-and-store obligation |
| Rule symmetry | The same sentence governs both stores (§4.3): what main refuses, alt refuses | Two admission rules for one rule id; the asymmetry is the very shape rule 16 says to migrate, not rationalize |
| False-reject risk | A briefly-future honest block (peer clock ahead ≤ 540 s + skew) is dropped, **not blacklisted** (§1), and is re-accepted on any later re-receipt — identical to the main path's existing semantics for the same block | No new rejects |
| Cost | One clause at the alt admission site (shared function per Q2's composition) | A rationale §; FOLLOWUPS row closes as ratified-asymmetry |

**Proposed ruling Q3: add FTL at alt admission.** Binding commitment: **#1 —
security** (a DoS bound on the acceptance path is a security property; the
promotion-only branch asks us to ratify its absence), with #3 seconding via
rule symmetry.

---

## 7. Implementation plan (runs only after §8 is signed; one PR with the ruling)

**Execution record (2026-09-01, this PR).** The plan below was executed as
written; the rule's single C++ owner is `cryptonote::shekyl_check_timestamp_rule`
(`blockchain.cpp:5568`, declared `blockchain.h` tail), consumed by the
vector overload (`:5617`, now FTL-bearing and const-correct), the main-path
window builder (`:5641`, carve-out deleted, genesis padding via the rule
fn), the alt admission site (`:2332` newest-11 truncation + `:2337` call),
and the template floor (`:1957`, `median + 1`). **Red observed first,
all four losing legs, each for its named reason** (candidate accepted by the
inherited code — "block verification context check failed"):
`gen_block_ts_at_median` (Q1 boundary), `gen_block_alt_ts_window_truncation`
(Q1 sub-a; the whole-chain averaged median g+780 accepted a g+800 candidate
the ruled newest-11 median g+840 rejects), `gen_block_ts_below_median_in_bootstrap`
(Q2; replaces `gen_block_ts_not_checked`, which asserted the deleted
carve-out), `gen_block_alt_ts_above_ftl` (Q3) — while `gen_block_ts_in_past`
and `gen_block_ts_in_future` stayed green through both phases. The Rust
side's mutation control: `>` → `>=` in `is_above_mtp` flipped the shared
`==` vectors red, then reverted clean; the C++ side's: `<=` → `<` in the
rule fn flipped the same vectors red through the unit suite, then
reverted clean.

One edge the plan had not named, caught by the first green run: the
genesis block itself traverses `check_block_timestamp` — once, when
`Blockchain::init` adds the locally constructed genesis to an empty
store — and an unconditional h ≥ 1 assert there kills core init. The
ruled sentence was sharpened (§4.3): the rule governs heights ≥ 1;
block 0 is pinned by the compiled genesis identity (a peer-supplied
height-0 block is rejected by `handle_alternative_block`'s existing
`block_height == 0` refusal, so the h == 0 arm is reachable only from
init).

Two review rounds (Copilot) tightened the landing further, both fixes
evaluated on the merits rather than adopted verbatim:

1. The FTL arm was rewritten to the saturating shape mirroring the Rust
   twin (`candidate > clock && candidate − clock > FTL` ≡
   `saturating_sub`), after a u64-boundary vector row demonstrated the
   naive `clock + 540` deadline wraps and rejects an in-bound candidate
   — observed red on the C++ side before the fix; Rust was already
   saturating. Twin parity of arithmetic *shape*, not just truth table,
   is the point: these two legs are the C3-cutover differential pair.
2. The template floor gained the §4.3 edge-refusal clause: at
   `M = now + 540` the constraint set is empty for the current second,
   so `create_block_template` revalidates its `M + 1` bump and returns
   false loudly instead of minting a self-rejecting template (rule 82 —
   an honest refusal beats a doomed template; the state self-heals on
   the next clock tick). The edge's existence and its self-healing are
   pinned deterministically on the pure rule owner
   (`template_edge_no_timestamp_satisfies_both_bounds`); the refusal
   arm itself runs against `time(NULL)`, and its deterministic harness
   needs the clock-seam design that census §10 batch **R9** (test seams
   in production consensus paths) already owns — recorded here, not
   silently skipped.

1. **Shared boundary vectors first** (rule 30: vectors before
   implementation): `docs/test_vectors/MTP_BOUNDARY_V1.json` — cases
   over a fixed 11-window: `median−1` / `median` (the `==` case) / `median+1`
   candidates with verdicts, an unsorted-window case (median is by sorted
   order), a padded-window case (Q2: fewer than 11 predecessors), and an
   alt-truncation case (window of >11 supplied history, only the newest 11
   count). Consumed by BOTH the C++ unit test and
   `shekyl-difficulty`'s tests — two implementations of one rule that don't
   share vectors will drift silently.
2. **Red first, both losing legs (rule 50):**
   - the `== median` vector observed **failing** against the live non-strict
     C++ before the comparison flips (the boundary test that never went red
     proves nothing);
   - a `now + 541` alt-admission case observed **accepted** by
     `handle_alternative_block` today, rejected after the FTL clause lands.
3. **C++ (consensus lands here first; stressnet runs it until the C3
   cutover):**
   - `:5519` comparison flips to reject `b.timestamp <= median_ts`;
   - Jagerman floor `:1953` becomes `median_ts + 1`; the currently
     unreachable uninitialized-`median_ts` read at that call site becomes a
     live hazard under any restructure — the FTL-fail arm sets the out-param;
   - alt window assembly truncates to the newest 11 before the median
     (surface 5), and the `h < 11` early-return is replaced by
     genesis-timestamp padding in window assembly (Q2) so one function owns
     FTL + median for both call paths (Q3 adds the alt FTL via that
     sharing).
4. **Rust:** `is_above_mtp` is already the ruled comparison — **aligned, not
   deleted**; its doc comment gains the ruling cite and states it is the
   future rewrite's implementation of this rule (zero production callers is
   the designed state until the C3 cutover). Padding/truncation live in
   window *assembly*, so the predicate's `&[u64; 11]` signature is untouched.
5. **Spec correction, refuted-not-superseded convention:** `DAA_LWMA1.md`
   §5.5 keeps "strictly greater" and gains a dated correction note at the
   ratification site: the "already implemented … preserved unchanged" premise
   was false at the tree (the inherited comparison was non-strict); the
   boundary was re-derived and re-ratified by C2-R3-Q1 (pointer here) — so a
   future reader can tell a reconsidered decision from one whose ground
   disappeared.
6. **Census, same PR:** CEN-C2 and CEN-C3 → bucket 2, class `ratified`,
   evidence → this doc (§3 counts: B2 14→16, B4 68→66; class split: 1
   `ratified-premise-refuted` → 0, `none` 56→55; §3.1 row C: B2 0→2, B4 2→0).
   CEN-C1: Q3's new rejection site appended to its **site column** (census
   §11.2 — a new callee that can reject is a row change, not a note) and the
   note updated to closed. §10 R3 row annotated ruled (the census is live
   text; only the archived walks are frozen), and §10's preamble counts
   ("Every bucket-3/4 row (70 = 68 + 2)", "counts sum to 70") re-worded to
   name 70 as the queue denominator **frozen at C1 close** with rulings
   tracked per batch row — the queue is a dispatch record, not a live bucket
   count, so it is not renumbered as rows leave bucket 4. §7-style
   decision-log entry added.
7. **Ledgers:** FOLLOWUPS rows :185 (alt-FTL) and :188 (MTP split) closed;
   CHANGELOG entries (boundary flip + alt-FTL are consensus changes; vector
   file addition per rule 30).
8. **No wire change expected:** all three rulings are validation-only; no
   persisted-block layout is touched. If implementation contradicts this,
   stop and re-read rule 42 before proceeding.
9. **Stressnet disposition:** stressnet daemons rebuild after the fix lands
   (stale-binary oracle pitfall); the estate rebuild already required by the
   V11 schema + genesis remint (§3) absorbs regenesis — stated in the PR so
   operators aren't left to discover it.

---

## 8. Ratification record

| Question | Proposed | Ratified (Rick) | Date |
| --- | --- | --- | --- |
| Q1 — MTP boundary | **Strict `>`**, with sub-decisions §4.2a (alt window = newest 11), §4.2b (template floor `median+1`), §4.2c (median = sorted index 5) | **Ratified as proposed**, sub-decisions a/b/c included | 2026-09-01 |
| Q2 — bootstrap carve-out | **Replace**: pad the window to 11 with the genesis timestamp; carve-out branch deleted | **Ratified as proposed** | 2026-09-01 |
| Q3 — alt-path FTL | **Add** FTL at alt admission (same clause, same clock semantics as main) | **Ratified as proposed** | 2026-09-01 |

Ratification came with an independent re-derivation of every §1 surface at
`dev @ 30cd547e2` (all confirmed, none corrected) and one scope ruling: the
§5.1 genesis-mint-timestamp question lands as a FOLLOWUPS row only — it must
not creep into this PR's diff.

Ratification note (scan result, §3): **complete** — the estate chain is
genesis-only (every peer at height 1, observed 2026-09-01); equality count 0,
invalidation 0.
