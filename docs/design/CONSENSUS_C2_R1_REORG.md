# C2-R1 — Reorg / alt-chain / checkpoints design round

**Status:** **OPEN — R1a MERGED (#596); R1b RATIFIED 2026-09-03 and BUILT (§4c) on `feat/c2-r1b-impl`; R1c next after C2-R0** (conditional on F-1's two path-sentences in this doc and F-2's exemption + three named red vectors in the build — both landed; see §4b and the round log). The implementation is PR #603; PR #600 was the proposal-only ratification record, merged 2026-09-03.
Second design round of the C2 program
([`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md) §10 batch R1, 20
rows). Steering (shekyl-core-00) adopted the three-sub-round structure
2026-09-02; Rick ratified **both** R1a lines the same day — C2-R1a-Q1
(delete the mechanism) and the CEN-G8 retirement (put to him separately as
the first retirement of a ratified bucket-1 row) — and the implementation
landed in the R1a PR. Rule 71 (network uniformity) was minted the same day
at Rick's direction (§4a) and R1b cites it rather than re-deriving it.
Nothing in §4/§5 is ruled yet. On R1c's close this document moves to
`docs/completed/` as the round's ruling record (rule 95).
**Pinned sha:** `bf317111f3412b548173bafda72f19e1bd1a7a0e` (`dev` tip,
2026-09-02 — the C2-R3 merge). Every `file:line` in this doc was located at
this pin; where a census citation drifted, both numbers are recorded.
**Identifier family:** `C2-R1a-Q1`, `C2-R1b-Q1…`, `C2-R1c-Q1…` (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) this PR, rule 94).
**Authority chain:** census §10 R1 + rows CEN-K1…K10, E1…E5, A1, A2, A4, D5,
D6; census §3.5 (main-vs-alt rule application) as the starting exhibit;
[`CONSENSUS_C2_R3_TIMESTAMPS.md`](../completed/CONSENSUS_C2_R3_TIMESTAMPS.md)
(round-shape precedent, including the rules-cross-to-Rust standing principle,
ruled 2026-09-01); rules 00 / 06 / 16 (incl. "documentation is not
verification") / 20 / 21 / 22 / 50 / 60 / 76 / 90.

**Scope fence (restated from the dispatch):** mempool policy beyond
CEN-K9/K10's reorg-sourced path is R7. Block-weight and fee constants are R2.
Header identity and the hardfork collapse are R4. Couplings recorded where a
row touches them; none opened.

---

## 1. Round structure — three sub-rounds, grouped by decision

The dispatch grouped the questions by topic (fork choice / checkpoints / alt
admission). Check-in regrouped them **by decision**, because a
checkpoint-forced switch is literally the second arm of the fork-choice rule
(CEN-K6 `:2555–2566`), so topic-grouping put one contract in two sub-rounds
and created a bidirectional ratification dependency. Steering adopted the
regrouping 2026-09-02:

| Sub-round | Rows | The decision | Status |
| --- | --- | --- | --- |
| **R1a** | CEN-E3, CEN-E4 (2) | Does the compiled-hash fast path — a consensus skip of PoW and FCMP — exist at all? Separable: rule 60-shaped existence question with its own examined-disposition record ([`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §74.2 left it "a shipping decision nobody has taken") | **RULED 2026-09-02, executed (§3, §3.8)** |
| **R1b** | CEN-K5, K6, K7, K8, D5, D6, E1, E2, E5 (9) | What decides the best chain — the difficulty arm, the checkpoint-forced arm, the depth question, and every override surface that can command a rollback — as one contract | Scoped (§4) |
| **R1c** | CEN-K1, K2, K3, K4, K9, K10, A1, A2, A4 (9) | What alt admission must verify, what the unvalidated alt store costs, and the acceptance topology around it | Scoped (§5) |

2 + 9 + 9 = 20 ✓. One PR per sub-round, ratify-then-build. **Sequence
updated 2026-09-02 (Rick, via the census-direction thread): R1a → R1b →
C2-R0 → R1c** — a **negative-space round** inserts before R1c. Its
premise, confirmed by the instrument's own data: the census is anchored
to `file:line`, so it is structurally incapable of minting a row for a
rule that *ought to exist and does not* (171 rows, zero with an empty
evidence column; `max_reorg|reorg_depth|reorg_limit` greps `src/` at
zero — Shekyl reorganizes arbitrarily deep with no rule anywhere to
say so). C2-R0 sources from postmortems and literature, mints `gap`
rows with an explicit `no site exists` marker, claims completion
source-based (never a sum — a denominator over rules-that-should-exist
cannot fail), and its **finding #1 is maximum reorg depth**. Its
deliverable into this round: a re-scoping note naming which of R1c's
nine rows it affects. **Authority status: briefed, pending dispatch —
not yet a tree artifact; cited here as direction, not as ratified
ground.**

**CEN-K1 spans all three groups** (three enforcement sites: the miner-tx
height-0 reject `blockchain.cpp:2287–2292`, E2's height-0 arm
`checkpoints.cpp:139–140`, D5's height ≥ 1 assert `blockchain.cpp:1579–1581`).
It is ruled in R1c and must name all three sites.

---

## 2. R1a ground at the pin

The mechanism under examination: the per-block-checkpoint fast-sync path.
A compiled-in *hash-of-hashes* table (`m_blocks_hash_of_hashes`) is loaded at
init; during sync, peer-supplied block-id chunks are verified against it
(`prevalidate_block_hashes`, called from
`cryptonote_protocol_handler.inl:2551`) and expand `m_blocks_hash_check`
(hash, weight) per height. Inside the expanded range, block connect trusts
the table instead of verifying.

Every claim below is verified at source at the pin (rule 16's corollary), not
carried from comments or census prose. Steering independently re-verified the
load-bearing ones 2026-09-02.

| # | Fact | Where |
| --- | --- | --- |
| 1 | Armed by default: `PER_BLOCK_CHECKPOINT=1` (`CMakeLists.txt:470–474`), `--fast-block-sync` default `1` (`cryptonote_core.cpp:143–146`), `m_fast_sync` default `true` (`blockchain.cpp:212`) | build + daemon args |
| 2 | Inert by data: all three shipped blobs are **zero bytes** (`src/blocks/checkpoints.dat`, `testnet_blocks.dat`, `stagenet_blocks.dat`; sha256 = `e3b0c442…`, the empty-string hash) | `src/blocks/` |
| 3 | Four `fast_check` arms in block connect: PoW skip `:5927`, pool-supplement NIC skip `:5976`, per-tx `check_tx_inputs` skip (= FCMP skip) `:6158`, and the GF-1 belt selector `:6309` | `blockchain.cpp` |
| 4 | CEN-E4's arm: the 4-arg `check_tx_inputs` wrapper returns success unchecked for `kept_by_block` below table height | `:3320–3328` |
| 5 | Pruned-weight substitution: a pruned block's weight is taken from the table; **with the table empty this arm always rejects** ("pruned, but we do not have a weight") | `:6194–6201` |
| 6 | The mainnet loader pin `expected_block_hashes_hash = 06c61040…` is **stale-impossible**: an inherited constant no Shekyl blob can match. Fails safe (refuses to load) — the mechanism's intended mainnet use is broken-as-shipped. The `if (m_nettype == MAINNET)` guard means **testnet/stagenet blobs load with no hash verification at all** (the `:7711+` parse is structural size checks only) | `:7676–7709` |
| 7 | The loader **flushes the entire tx pool** as a side effect when hashes load (inherited FIXME) | `:7745–7762` |
| 8 | **Zero test references**: no occurrence of `PER_BLOCK_CHECKPOINT`, `blocks_hash_check`, or `fast_check` anywhere under `tests/`. The `=0` compile shape is never built — consensus code in two compile configurations, one untested, the other's skip arms unexercised | grep, both directions stated: presence in `src/` at the six sites above, absence in `tests/` (full-tree grep, unpiped exit codes) |
| 9 | Sibling/functional sweep **clean** (unpiped, `grep` exit 1, zero lines): no reference to `fast-block-sync` / `GetCheckpointsData` in shekyl-dev, shekyl-gui-wallet, shekyl-web, shekyl-mobile-wallet, `tests/`, `utils/`. In-repo consumers: `daemon.cpp:141`, `blockchain_import.cpp:794` — both in deletion scope, both with `nullptr` alternates in their `#else` arms | cross-repo grep |
| 10 | p2p consumers: `has_block_weights` gates whether pruned spans may be requested (`protocol_handler.inl:2002`); with the table empty the predicate is always false, so the node already always requests full blocks — the deletion collapses this gate behavior-identically | `protocol_handler.inl:1990–2005` |
| 11 | E1's checkpoint zone does **not** skip PoW — the inherited skip-before-checkpoints was already removed upstream (comment `:5896–5901`); the zone only adds a hash-equality requirement. The pool-cached `can_skip_fcmp` (`:6172`) is a separate, ratified, embargo-load-bearing skip — **not touched by this round** | `blockchain.cpp` |

---

## 3. R1a ruling (C2-R1a-Q1) — RATIFIED 2026-09-02

**Ruling (ratified as proposed): delete the per-block-checkpoint fast-sync mechanism
entirely.** No replacement, no dormant retention. CEN-E3 and CEN-E4 become
`ruled-removed`; the reopening criterion below governs reintroduction.

The keep-dormant horn is rejected on rule 21's form: keeping it means
building verification and tests *now* for a mechanism with no data (the
testnet/stagenet unverified-load hole and the two-compile-shape test gap are
real work someone must do to keep it honestly), and watching two `.dat` trust
surfaces forever. Reject-now-with-reopening-criteria is the disciplined
shape. The DRP §74.2 initial-sync concern is future and speculative
(v3-from-genesis: there is no history to fast-sync, rule 60); it is exactly
what the reopening criterion is for.

### 3.1 The G8 consequence — its own ratification line

**This ruling retires a bucket-1 ratified row: CEN-G8** (the GF-1 fast-path
debit belt, [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §9.6,
[`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.5 step 5) — the first
time a C2 round retires a previously-ratified row, so it is put to Rick
explicitly, not inside a deletion inventory.

Jobs enumeration, verified at source: the belt's one job is debit-auth
pinning **when `fast_check` skips per-tx verify**. The primary pin's host
`check_archival_bond_post_input` is called at `blockchain.cpp:3831` inside
`check_tx_inputs`' per-tx path, which becomes unconditional at block connect
once `fast_check` goes. The belt's selector
(`fast_check && bond.bond_debit > 0`, `:6309`) is structurally dead after the
deletion. One job, covered by the primary; the belt's stated purpose
(fast-syncing and fully-verifying nodes agreeing) is the job the
now-unconditional primary performs. G8 retires with pointers; the gate-6 and
gate-4 docs receive closure notes; census counts adjust in the same edit.

### 3.2 Wargame

Asset: a node's conviction that every connected block carries valid PoW and
valid tx inputs. Suppressor-writers of that conviction, enumerated: E3's
`fast_check` is the **only** main-path suppressor; `can_skip_fcmp` is a
separate ratified skip (stays, §2 row 11); E1's zone adds a requirement,
never removes one.

| Adversary | Channel | Today | After deletion | Direction check |
| --- | --- | --- | --- | --- |
| T1: data-only PR or release packager populates a `.dat` | compile-time artifact | mainnet fails safe on the stale pin; testnet/stagenet load **unverified**; a "data update" PR flips PoW+FCMP off without reading as a consensus change | channel gone — reintroduction requires code, which requires the named design round | faces the artifact channel, covers all three networks; the marginal risk was the legitimate-*looking* one-line shipping decision (a security downgrade must be a conscious act) |
| T2: peer feeds crafted hash chunks | `NOTIFY_RESPONSE_CHAIN_ENTRY` → `prevalidate_block_hashes` | chunks verified against the compiled table; empty table → early return; no exposure | surface deleted | was already inert; deletion removes the code path, not a live defence |
| T3: future maintainer builds the `=0` shape, or the ifdef pair drifts | compile configuration | untested configuration of consensus code | single compile shape | collapses the unconverged-configuration class |
| T4: the keep-dormant horn itself | maintenance | verification+tests owed now for a data-less mechanism; two `.dat` trust surfaces watched forever; G8 carried forever | cost zero | rule 21: reject-now beats pre-provisioned flexibility |

### 3.3 Behavior preservation — the acceptance evidence

Every deleted arm is unreachable with empty data today: `fast_check` always
false, E4's `height < 0` never true, `prevalidate_block_hashes`
early-returns, `has_block_weights` always false, the pruned-weight arm
already always-rejects. **The full existing C++ suite green across the
deletion is the evidence.** No red-first test exists for removing unreachable
surface (rule 50's discipline here is the build plus the suite), and no
standing grep gate is added — no recurrence vector, and a gate that cannot
fire on a plausible edit is convention theater.

### 3.4 Fences

- `NOTIFY_RESPONSE_CHAIN_ENTRY`'s block-weights wire field becomes unread but
  **stays** — deleting it is a wire change owned by the P2P lane (the LV-3
  field-parity class). Coupling recorded here.
- `--fast-block-sync` removal is **operator-visible**: a config carrying the
  flag fails startup on an unknown option. Pre-genesis, acceptable — stated
  here so it is approved, not discovered.
- The pruned-block reject arm (`:6194`) stays, now unconditional.
  Pruned-*daemon* mode is TJ-lane, post-genesis, node-local — unaffected.

### 3.5 Reopening criterion (the falsifier)

A fast-sync trust mechanism may be reintroduced only by a design round that:

- (a) names the **trust root** — who computes the hash set, how it is
  verified, how it ships;
- (b) rules each skipped verification **explicitly by name** (PoW / FCMP /
  NIC);
- (c) states the **reach policy** relative to tip;
- (d) lands with tests exercising covered and uncovered ranges in the same
  build.

**Trigger (interim absolute, provisional):** full initial sync on the rule-76
provisioning-floor device (Pi 4), measured or projected from measured per-tx
verify throughput, exceeding **72 hours**. This number is an interim pin so
the trigger can actually fire — it is replaceable without a design round by
the node-onboarding lane's figure whenever that lane pins one
(DRP §74.3 handed the question there; §74.2's "unmade shipping decision" is
hereby made: **not shipped**, reopening as above).

### 3.6 Deletion inventory (one PR: docs + code)

`PER_BLOCK_CHECKPOINT` (CMake + define + all `#if` regions) ·
`m_blocks_hash_check` · `m_blocks_hash_of_hashes` · `HASH_OF_HASHES_STEP` ·
`load_compiled_in_block_hashes` + `expected_block_hashes_hash` ·
`prevalidate_block_hashes` · `has_block_weights` ·
`is_within_compiled_block_hash_area` · the 4k jettison (`:6924–6928`) ·
the pruned-weight substitution arm · E4's wrapper arm · all four `fast_check`
arms incl. the G8 belt · `--fast-block-sync` + `m_fast_sync` ·
`GetCheckpointsCallback` plumbing (`daemon.cpp`, `cryptonote_core`,
`blockchain_import`) · `src/blocks/` (`blocks.cpp/.h`, three `.dat` files,
its CMake). Census: E3/E4/G8 rows + §3/§3.1 counts in the same edit.

### 3.7 Disposition arithmetic

R1a rules **2** of R1's 20 (E3 `ruled-removed`, E4 `ruled-removed`); CEN-G8
retired as an absorbed out-of-batch consequence with its own ratification
line (§3.1), Rick-approved verbatim. 18 rows remain: R1b (9) + R1c (9).
Sum: 2 + 9 + 9 = 20 ✓. Census: E3/E4/G8 → bucket 3, counts 86/16/5/64
(sum 171 preserved; reproduce with the census §3 command block).

### 3.8 Execution record

- Deletion executed exactly per §3.6 plus three additions found in
  execution: the `src/CMakeLists.txt` `if(PER_BLOCK_CHECKPOINT)` wrapper
  (caught by the full-inventory sweep after the body was deleted), the
  three mock-interface stubs in `tests/unit_tests/node_server.cpp`
  (:100/:104/:105 — found by Rick and steering's re-sweep; build-surface
  dependencies, not coverage), and the `--blocksdat` output mode of
  `shekyl-blockchain-export` (`blocksdat_file.{cpp,h}`) — the *generator*
  of the deleted mechanism's data blob, dead with its consumer.
- **Sweep discipline (steering's correction, adopted):** the original
  "zero test references" claim had grepped a 3-term *sample* of the symbol
  set — an absence claim scoped to a sample proves nothing about the set.
  The landed verification sweeps **every §3.6 inventory symbol** (16
  terms) across `src/ tests/ utils/ contrib/ cmake/ CMakeLists.txt
  Makefile` and the four sibling repos, unpiped exit codes, totals stated:
  repo = 1 hit (the CMake wrapper straggler, then fixed to 0), siblings =
  0 hits (exit 1).
- `should_ask_for_pruned_data` collapses to an unconditional `false` —
  behavior-preserving twice over (the deleted `is_within` check already
  forced false, and no Shekyl node holds a pruning seed); the pruned-span
  request machinery it gated keeps its other consumers untouched.
- The `NOTIFY_RESPONSE_CHAIN_ENTRY` handler's `prevalidate_block_hashes`
  call site collapses to nothing: its two live effects (empty-ids,
  weights-size mismatch) are both already enforced by earlier guards in
  the same handler (`:2509`, `:2521`).
- `check_debit_auth_single_source.sh`: the required "block fast-check
  debit" arm removed (three sites remain); gate re-run green — the
  retirement's blast radius reached the gate that certified the belt.
- Rule 71's gate `scripts/ci/check_network_uniformity.sh` landed wired
  into `ci/grep-gates`, allowlist seeded with the **7** surviving public-
  nettype branches (annotated with owners) — the check-in's "6" was an
  under-count: the site census had excluded lines containing FAKECHAIN,
  and the compound `blockchain.cpp:473` line
  (`m_nettype == FAKECHAIN || m_nettype == STAGENET`) carries a public
  STAGENET comparison the exclusion filter swallowed. An exclusion
  filter can eat a hit the same way a pipe eats an exit status; the
  Copilot round caught the count drift. The gate enforces a
  **bijection** (exact-text hit↔entry, per-entry presence with observed
  counts, and hit-total == entry-total, so a copy-pasted duplicate of an
  allowlisted branch goes red) and was **bitten in three directions
  before trust**: a planted `if (m_nettype == MAINNET)` in scope went
  red (unlisted-hit arm), a verbatim duplicate of an allowlisted branch
  went red (bijection-total arm — the case prefix-matching would have
  passed), a mutated allowlisted branch went red (stale-entry arm),
  restore green. **Second review-round correction:** the matcher's first
  two revisions matched `==` only — blind to `!=`, which keys control
  flow on the network just as hard; the live
  `update_checkpoints` guard (`if (m_nettype != MAINNET) return true;`,
  `cryptonote_core.cpp:254`) was invisible to the gate *and* missing
  from §4a's ground. Matcher widened to `[!=]=` (both scans), the guard
  allowlisted as the E5 mechanism's third wiring site (count 7→8), and
  a planted inequality branch bitten red before trust. **Third
  review-round corrections:** (i) the matcher's `[^)]*` span stopped at
  the first `)`, so a compound condition
  (`if (feature_enabled() && m_nettype == MAINNET)`) evaded it —
  widened to a non-greedy statement-bounded span and a planted compound
  branch bitten red (the gate's fifth observed-red direction); (ii) the
  §3.1 claim "the gate-6 and gate-4 docs receive closure notes" had
  landed no notes — both closure notes now exist
  ([`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §9.6,
  [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.5 step 5) —
  a status claim written before its act, caught by review; (iii) the
  inventory sweep had excluded `docs/` wholesale, but three OPERATIONAL
  docs carried live instructions for the deleted mechanism
  (`USER_GUIDE.md` advertised `--fast-block-sync`,
  `RELEASE_CHECKLIST.md` required generating `checkpoints.dat` and
  updating the deleted hash constant, `EXECUTABLES.md` documented
  `--blocksdat`) — all removed; the same targeted docs sweep also
  caught a **fourth** site review missed: `SHEKYL_P2P_PROTOCOL.md`'s
  worked example (born in #594, merged into this branch mid-round)
  described the mechanism in present tense — converted to a
  past-tense record with the deletion noted. Operational docs are
  sweep scope; only round-record mentions are exempt. **Fourth
  review-round corrections:** (i) the matcher became fully
  spelling-independent — `if ?\(` covers the no-space style, the
  comparison matches a public constant on either operand side under ANY
  variable name (an alias like `if (network == MAINNET)` is the same
  rot), the separate unjoined reversed-spelling scan was absorbed into
  the one statement-joined scan (its old form missed wrapped reversed
  branches), and a `switch`/`case MAINNET:` arm closes the last
  spelling; (ii) collection failures became LOUD — a stripper failure
  on any file fails the gate (an unreadable file is not a match-less
  file) and an empty fence directory is a gate error, never a PASS
  (rule 46/47); six more planted evasions observed red (no-space,
  aliased operand, wrapped reversed, switch, aliased switch, unreadable
  file) — every enforcement arm has now been observed red at least
  once; (iii) three code comments still described the retired CEN-G8
  arm in present tense (`blockchain.cpp` emission-vin fail-closed note,
  `shekyl_ffi.h` debit-pin selector note, `debit_auth.rs` module doc) —
  reworded to state the live constraint with the belt as past
  provenance; a mechanism-prose sweep across `src/` + `rust/` found no
  fourth instance (the `blockchain_db.h` "fast-sync resumption" hit is
  the curve-tree checkpoint family, a different mechanism).
  **Fifth-round correction (a body-carried finding that never became a
  review thread — the reason suppressed findings get read):** rule 71's
  closing line still said both checkpoint instances "were resolved",
  repeating the completed-migration claim in a sentence the round-3
  tense fix did not sweep; now states one deleted (C2-R1a), one queued
  (C2-R1b). Same lesson as the stranded-docstring class: sweep the
  CLAIM's wording everywhere it was restated, not just the flagged
  line.
- **A fourth residue class the symbol sweep structurally cannot see:**
  fourteen test call sites passed the removed trailing parameter
  *positionally* (`init(..., 0, NULL)` in `block_weight.cpp`,
  `chaingen.cpp`, `output_distribution.cpp`, `scaling_2021.cpp`,
  `daemon_submit_shims.cpp`, `txpool_ref_age.cpp`, `pruning.cpp`,
  `economics_b5_fee_coinbase.cpp`, `txpool_relay_timers.cpp`,
  `archival_bond_post_integration.cpp`, `rpc_facts_shims.cpp`,
  `long_term_block_weight.cpp`; `core->init(vm, nullptr, nullptr)` ×3 in
  `node_server.cpp`) — a bare `NULL` names no symbol, so no
  inventory-term grep can find it. For a signature change the **compile
  is the authoritative sweep**; the symbol sweep covers only named
  references. Both were run; each caught what the other cannot. Two of
  the fourteen additionally hid from intermediate filtered greps behind
  a macro line-continuation backslash and a dot-call spelling — the
  authoritative form was one *unfiltered* pattern over the whole tree
  with the total stated (6 hits: 3 already-valid, 2 real, 1 in-signature
  default).
- Acceptance evidence per §3.3: full C++ build (BUILD_TESTS=ON) + ctest
  across the deletion (results recorded in the PR). First ctest attempt
  reported "No tests were found" with exit 0 — a vacuous green refused on
  rule 47's bar; the suite was rebuilt with tests enabled and re-run.

---

## 4. R1b scope (fork choice + checkpoint zone as one contract) — not yet ruled

Rows: CEN-K5, K6, K7, K8, D5, D6, E1, E2, E5. Ground facts already banked at
the pin, to be built on (each verified at source; hypotheses marked):

### 4a. Addendum (Rick, 2026-09-02): the second checkpoint mechanism also
forks on nettype — grounded at source

There are at least two separate checkpoint mechanisms in this tree, and
both fork on nettype in ways that make testnet unable to validate mainnet.
The first was CEN-E3/E4 (§2 row 6: the trust-root check was
`if (m_nettype == MAINNET)`, so testnet/stagenet loaded the compiled table
with zero verification) — deleted by §3, so moot. The second is **live and
is R1b's subject**:

- **The lead exhibit — `cryptonote_core.cpp:254`** (found by the R1a
  Copilot round; two steering reads of the same function had missed it,
  both having started below its opening guard):
  `core::update_checkpoints()` opens with
  `if (m_nettype != MAINNET) return true;` — note the **`return
  true`**. Off mainnet the periodic reload does not merely skip, it
  reports **success**: a caller cannot distinguish "checkpoints
  updated" from "not applicable here", so any future code branching on
  that return inherits a lie. Not a silent skip — a **silent false
  positive**, the rot shape producing an affirmative wrong answer.
  This is the *periodic* path (called from the protocol handler on
  incoming blocks, 600 s throttle), so re-homing only the init block
  would still leave live checkpoint reload mainnet-only; the
  uniform-wiring decision must take **both** sites. Its tail calls
  `graceful_exit()` on a failed reload — priced in Q2b. An
  **inequality** spelling, which is also why the gate matches `[!=]=`,
  not `==` alone.
- `cryptonote_core.cpp:326` (was `:332` at the §4 pin; drifted by the
  R1a deletion) wraps the **entire** operator-checkpoint init block —
  `init_default_checkpoints`, `set_checkpoints`, **and**
  `set_checkpoints_file_path` — in `if (m_nettype == MAINNET)`. Off
  mainnet, `m_checkpoints_path` stays `""`,
  `boost::filesystem::exists("")` is false, and the JSON loader
  (`checkpoints.cpp:195`) no-ops behind an L1-only log ("file not
  found" — invisible at default verbosity) **and returns success** —
  the same reports-success shape as `:254`, one layer down.
  **The operator-override path —
  the exact mechanism whose forced-rollback semantics R1b rules (CEN-K6's
  checkpoint arm, E2, E5) — is unreachable by construction on testnet and
  stagenet.** As the code stands, a checkpoint-forced-switch ruling would
  ship with no network on which an operator could rehearse it before
  touching mainnet.
- `checkpoints.cpp:181–193` (`init_default_checkpoints`) has per-network
  early-return arms — currently all no-ops (zero compiled checkpoints),
  i.e. structurally divergent, behaviorally identical: the shape that
  rots.

The generalization is **rule 71** (minted 2026-09-02 at Rick's direction,
this PR): nettype selects data, never control flow, on the
consensus/validation surface; a real behavioral divergence must be named,
ratified, and loud — it can never just fall out of an `if`. The failure
mode: once nettype selects a code path, "testnet passed" degrades from
"this logic is correct" to "the logic testnet happens to run is correct".
Enforcement landed with the rule (§3.8): the grep gate over
`cryptonote_core/ + checkpoints/ + blockchain_db/`, both equality
operators, allowlist seeded at 8 and annotated (§3.8 records the 6→7→8
count corrections). R1b therefore owes, citing rule 71 rather than re-deriving
it:

1. **E2/K6/E5 re-homing:** decide whether the operator-override wiring
   goes uniform across all three public networks. Rick's stated instinct:
   yes, unconditionally — an operator should be able to rehearse a
   checkpoint override on testnet before ever touching it on mainnet, and
   pre-genesis there is no cost. The wargame prices the trust surface
   uniformly (E5's `pt.first − 2` rollback then exists on every network).
2. **The positive check (steering's addition):** the grep gate only
   catches *new* branches; the stronger corollary is that the same
   validator tests run against **all** network parameter sets — a
   parameterized cross-params suite proves there is nothing to branch on.
   R1b proposes it for the surface it touches.
3. The unpopulatable difficulty-checkpoint twin (`m_difficulty_points`,
   §4 item 5) is ruled in the same package.

FAKECHAIN's silent consensus skips (CEN-B5's root check, the CTTypeNull
waiver) are the same class and are **batch R9's subject**; R9 inherits
rule 71's named-ratified-and-loud exception discipline (the
`SEEDHASH_EPOCH` override is the compliant counter-pattern: armed,
datadir-pinned, loud) rather than re-deriving the principle.

1. **The pop machinery has four writers**, and any depth ruling must cover
   all of them: (i) `switch_to_alternative_blockchain` (`:1430–1437`);
   (ii) `check_against_checkpoints` (`:6800–6828`) — an operator-loaded JSON
   checkpoint conflicting with the local chain **forces rollback to
   `pt.first − 2`**; (iii) the `pop_blocks` daemon console command + RPC
   (`core_rpc_server.cpp:1652`); (iv) `blockchain_import` (offline).
2. **No reorg-depth bound exists anywhere in the fork-choice layer.** E2 is
   vacuously permissive (zero checkpoints), so a fork from height 1 is
   admissible. Meanwhile `ARCHIVAL_REORG_DEPTH_BLOCKS = 720` is a
   load-bearing assumption across the Rust engine (pscan ceilings, sealing
   runs, swing bounds; `swing.rs` const-asserts `REORG_DEPTH < EPOCH_BLOCKS`;
   `segment.rs:20` duplicates the constant) **with zero occurrences in
   `src/` or `config/`** — surfaced to Rick by steering as a finding in its
   own right, 2026-09-02.
3. The DB pop side is journal-driven pre-image restore
   (`blockchain_db.cpp:666–740`: slash / epoch-close / emission-claim /
   unbond / holdings / rebond reverts with load-bearing order). The epoch
   frozen rows (`R_market`, `Σwork`, budget) delete on pop and re-derive on
   re-close from retained accrual rows. *Hypothesis to settle in R1b: the
   structural depth floor of a survivable pop is the retention horizon
   (`W = 26` settlement epochs ≫ 720), not 720 — the exact break depth and
   its failure shape (loud vs corrupting) must be read before the depth
   ruling.*
4. E5's live surface: `<data_dir>/checkpoints.json` auto-loads at init
   (`cryptonote_core.cpp:342–344`, no flag needed) and re-loads on incoming
   blocks throttled to 600 s (`protocol_handler.inl:712`); a conflicting
   checkpoint triggers the `pt.first − 2` rollback.
5. A **difficulty-checkpoint twin surface** exists and is unpopulatable
   today: `m_difficulty_points` is consumed at init
   (`check_difficulty_checkpoints` `:1195`, `recalculate_difficulties`
   `:1218`) but its only writer is `add_checkpoint`'s 3-arg form, and the
   JSON `t_hashline` carries height+hash only. Dead surface in E5's family.
6. K6's comparison at `:2567`: `main_cd < alt_cd` — strictly greater
   switches, equality keeps main. The checkpoint-forced arm (`:2555–2566`)
   switches with `discard_disconnected_chain = true` — demoted blocks are
   **dropped**, not re-added as alts (asymmetric with the difficulty arm).
7. D5's stitch (`:1602–1644`) is post-LWMA-port reworked: `chain_height =
   bei.height − 1` matches [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) §5.6's
   consumer contract, and the window arithmetic produces exactly N+1 entries
   above the short-circuit threshold (derived from the contiguity invariant
   of `build_alt_chain`). The census's "stitch stays inherited/unexamined" is
   part-stale; what remains for R1b is ratifying the *selection construction*
   and the ownership call (check-in lean: the selection arithmetic + window
   invariant cross to Rust; DB fetches stay C++; `check_hash` already lives
   behind `shekyl_difficulty_check_hash`, so a fork-choice/window family in
   `shekyl-difficulty` joins an established home).
8. D6's zero-guard sites at the pin: main `:5887`, alt `:2398` — both
   `CHECK_AND_ASSERT_MES` log-and-return-false, per the C1 correction.

Rule-vs-orchestration leans recorded at check-in (steering-endorsed, to be
confirmed or refuted in the proposal): K6 crosses; D5's selection crosses;
E1 crossing deferred to the existence ruling (a hash-equality crossing alone
makes the shim thicker than the rule — the anti-target); K5/K7 orchestration;
K8 ratify-and-keep (deleting the field would change the persisted
`alt_block_data_t` layout — rule 42 fence).

## 4b. R1b rulings — RATIFIED 2026-09-03 (as amended at `ad72e1bc9`, + F-1/F-2 below)

**Section pin: `4b9807c5e`** (dev tip = the R1a merge; §1–§4 sites are at
the header pin `bf317111f`, and where a §4 site drifted both numbers are
recorded in place). Rows ruled here: CEN-K5, K6, K7, K8, D5, D6 (Q1) +
CEN-E1, E2, E5 (Q2) = 9; with R1a's 2 and R1c's 9: 2+9+9 = 20 ✓. Each
ruled sentence is stated exactly once, here; census rows will point at
this section rather than restating it (the R1a review cycle grew on
restated claims).

### C2-R1b-Q1 — the fork-choice and depth contract (K5, K6, K7, K8, D5, D6)

**Q1a (fork choice, ratifying the inherited shape with its rationale
stated).** The best chain is decided at alt admission by **strictly
greater cumulative difficulty — equality keeps the incumbent**
(`blockchain.cpp:2562`); an operator-checkpoint match on the alt chain
**forces** the switch regardless of difficulty (`:2550`). Promotion
re-validates every block through the full main-chain path; any failure
rolls back to the pre-switch chain and discards the failing suffix
(K5, `:1399`). Demotion asymmetry ratified as **intentional mechanism,
not accident**: a difficulty-triggered switch re-admits demoted blocks
as alts (K7), but a checkpoint-forced switch **discards** them
(`discard_disconnected_chain = true`) — because a checkpoint-forced
switch can promote a *lighter* chain, and re-admitting the heavier
demoted chain as an alt would let it immediately re-trigger a
difficulty switch back: the discard is the flip-flop terminator. K8
(alt `already_generated_coins` approximation) is **ratified-and-kept**:
by construction, documented at site, nothing consensus-bearing reads
it, and deleting the field would change the persisted
`alt_block_data_t` layout (rule 42 fence). CEN-K5b (bucket 1) is named
and preserved: the witness capture-before-pop / re-supply-at-promote
ordering is untouched by everything ruled here.

*Falsifier (Q1a):* reopen on evidence of an attack that exploits the
admission-before-full-validation ordering at a cost promotion's
re-validation does not contain — R1c's cheap-fork wargame seeds are the
watch-list; a confirmed sub-51% forced-reorg cycle reopens this ruling,
not just R1c's.

**Q1b (crossings — rule 20/71, joining the established
`shekyl-difficulty` family).** The fork-choice comparison crosses to
Rust: a pure `shekyl-difficulty` predicate over the two cumulative
difficulties (u128 as the FFI's existing two-u64 halves) plus the
checkpoint-match flag, exported beside `shekyl_difficulty_check_hash` /
`lwma1_next`; the C++ switch machinery consumes its verdict
(orchestration stays). CEN-D5's window **selection arithmetic** — the
stop/count/start-offset derivation and the exactly-N+1-above-threshold
invariant (`:1557` region) — crosses as a pure window-assembly
function; the DB fetches stay C++ (a thicker crossing would put LMDB
reads behind the FFI: the anti-target). CEN-D6's zero-difficulty
reject is ratified as the marshaling belt it is: the C++ call sites
keep the guard on the FFI result (both sites) — a marshaling layer
that swallowed the sentinel would convert a difficulty-function
failure into a silently accepted block, the verdict-eaten-by-an-
intermediary failure this codebase bans wherever it appears (rule 46
is the shell-gate instance of the same principle; cited as analogy,
not authority). **CEN-E1 does
NOT cross — a decision, not a deferral** (rule 22): the checkpoint set
is a `std::map` filled by an epee JSON loader — glue and state under
rule 20's "C++ if all of" — and its predicate is a hash equality with
no derivation content; crossing only the equality makes the shim
thicker than the rule. The rule content crosses if and when the
checkpoint set itself moves into the Rust store — named owner: the DRS
program / census batch R8. (Trigger state re-checked 2026-09-02 after
CSR landed as PR #595: the CSR reconciliation ruled the store-schema
decision and mapped 18 store rows with **zero** checkpoint mentions —
the decision landed, the state has not moved and is not scheduled to;
the trigger is not live.)

*Falsifier (Q1b):* the crossings land red-first with shared vectors per
the R3 pattern; the E1 no-crossing decision reopens automatically when
DRS/R8 moves checkpoint state across the boundary.

**Q1c (the depth ruling — the batch's centre).** Ground, verified at
source this round: the four pop writers all traverse one landing point
(`BlockchainDB::pop_block`); the revert journals are **never pruned**;
the retention prune (fired *inside the consensus epoch-close hook*,
`db_lmdb.cpp:8446`, so **every node prunes identically at the same
heights**) deletes serve-credit rows, frozen epoch aggregates, accrual
rows and witnesses below `tip − W` settlement epochs, and those
deletions are **un-journaled**. Failure shapes enumerated: the
bond-record reverts throw FATAL on a missing subject (loud); the
serve-credit bit removal is `MDB_NOTFOUND`-tolerant; and past the
prune horizon the corrupting arm is real — a pop crossing into a
partially-pruned epoch re-derives budget/Σwork/R_market on re-close
from accrual rows that no longer exist, **silently wrong**. So today's
depth ladder is: `[0, 720]` engine envelope; `(720, ~W·SEB ≈ 260k)`
DB-survivable and loud; beyond the horizon, **silent consensus-state
corruption**.

**Ruled: a pop deeper than the archival retention horizon is refused,
loudly, at the landing point.** `BlockchainDB::pop_block` refuses to
pop a block below `tip_at_pop_start − REORG_HARD_HORIZON`, where
`REORG_HARD_HORIZON` is **derived from the same constant source as the
retention prune** (steering-verified at source: the prune is driven
from the epoch-close hook by `prune_below_epoch_at_height(height,
MAX_CLAIM_AGE_W)` with `max_claim_age_w: 26` pinned in
`config/consensus_constants.json` — height in, config constant, same
answer on every node; deriving the refusal from that same source is
the **load-bearing half of the ruling**, because a second constant
would mint exactly the drift twin this program keeps deleting). The
first draft derived the floor from `tip_at_pop_start`; review round 2
found the hole that formulation leaves open, and the fix strengthens
the same-source property into a **same-event** one. **The hole:** a
tip-derived floor moves with the tip — repeated pops (or a restart
between commands) recompute a lower floor from the new, lower tip,
and the node can iteratively walk below rows that were pruned when
the tip was at its historical high-water mark; pruned rows do not
come back when the tip retreats (the prunes are un-journaled — this
round's own ground). **The ruling therefore uses a persisted,
monotonic watermark:** the prune, which already knows exactly what it
deleted, records the highest `prune_below_epoch` it has ever applied
— written in the **same write txn as the prune itself**
(`db_lmdb.cpp:8446` site), monotonically non-decreasing, one writer.
`pop_block` refuses any pop whose target height falls below
`epoch_open_height(watermark)`. No inference from the current tip, no
recomputation to drift, no reset on restart: the floor is the prune's
own durable receipt for what it destroyed, and the corrupting arm
(the partially-covered epoch at the boundary) sits exactly above it —
the epoch-boundary truncation *is* the margin. No separate slack
constant, no new constant at all, no twin.

**F-2 (Rick's ratification condition — the watermark is exempt from
pop reversal, by design):** pops already traverse an epoch-close
reversal path (`BlockchainDB::pop_block` →
`revert_archival_epoch_close_at_height`, `blockchain_db.cpp:676`), and
the watermark is written in that same epoch-close event's txn — so a
build that symmetrically reverted it on a pop across an epoch-close
boundary would reopen the walk-down hole through the back door. **The
watermark records destruction, which pops cannot undo: monotonic, one
writer, never lowered, exempt from every revert.** Three named red
vectors bind the build: (i) pop across an epoch-close boundary — the
watermark is unchanged; (ii) pop to exactly
`epoch_open_height(watermark)` — allowed; (iii) one block below —
refused. **Placement, stated so the next reader cannot cover the
wrong surface — corrected by review round 2, and the correction is a
worked instance of rule 16's corollary against this round's own
prose:** the first draft called the no-arg `pop_block()` overload
(`blockchain_db.cpp:247`) "the add-failure undo," sourced from its
header comment — and a repo-wide caller search finds **zero callers**:
the actual add-failure undos (`blockchain.cpp:6469`, `:6479`) call
`pop_block_from_blockchain()`, which reaches the **arg-taking**
overload (`:667`), as do both direct Blockchain-layer callers
(`:579`, `:819`). The header comment describes an intent no code
serves; the doc had repeated the comment as fact. **The check lives
in the arg-taking overload's body — now the only body: the build
DELETES the caller-less no-arg overload** (rules 15/60 — a dead
overload beside a guarded one is a standing invitation to bypass),
making the placement question moot by construction. The landing point is chosen **by property,
not by name**: it is the single funnel every pop writer traverses —
the switch, the operator-checkpoint rollback, the RPC/console, the
importer, and the add-failure undo alike — so if the DRS store
decomposition re-homes the pop path, the check relocates by
re-finding that funnel property, not by grepping for a class name.

**Scope of this ruling, stated so the round is not read as answering a
question it does not answer (Rick's characterisation, adopted: this is
"a finality rule wearing storage clothes"):** Q1c bounds **storage
recoverability** — the depth past which the database's own retention
design makes reversal unsound. That bound is on the order of a year of
blocks and therefore **never binds against a real attacker**. A
*security* depth bound — the rule that decides how deep a reorg the
network should ever accept — is a **separate, strictly tighter rule at
a different layer, owned by C2-R0** (its finding #1), and the two
compose (any security bound N ≪ this horizon) rather than compete.
The census could not surface that rule because no `file:line` exists
for it; that gap is C2-R0's founding case. The
refusal is a hard error: the reorg/rollback/RPC caller fails with a
message naming the horizon and the remedy (resync), never a silent
partial state. This is **not a fork-choice rule**, and — corrected for the watermark
form, because the earlier "introduces no new subjectivity" sentence
was verified of the tip-derived floor and is **false of the form that
ships** — the honest claim is: **the floor is deliberately node-local,
because the hazard is node-local.** A persisted watermark is this
node's state; two nodes at the same tip can hold different watermarks
if one saw a higher tip and reorged back, and their refusal depths
then differ. That is correct, not a defect: a node that pruned cannot
safely revert and a node that did not can — the refusal is a **local
data-availability property, not a consensus rule**, and the
consequence of divergence is that some nodes halt where others follow
(a liveness/partition consequence, never a chain split; every halting
node halts loudly with the same remedy). **Uniformity was never the
property that made the floor safe — durability was.** The ruling
converts an existing silent-corruption arm into a loud refusal.

**F-1 (Rick's ratification condition — refused-pop semantics on the
two non-interactive paths, because "every halting node halts loudly"
must be specified, not assumed):**
(a) a **network-driven switch** whose rollback is watermark-refused
must put the node into a **loud, persistent, operator-visible
non-following state** — at minimum a sticky degraded flag surfaced on
RPC/status and logged at every re-attempt — never a silent
healthy-looking continue: a refuse-and-continue node is a live
minority-chain participant serving stale data, which *is* the split
the ruling forbids.
(b) a **checkpoint chain-conflict** whose saturated rollback is itself
watermark-refused **fail-stops** with the named-output obligation
(file, height, both hashes, the watermark, remedy: resync) — posture-
consistent with the JSON-conflict arm; the daemon never continues
running in contradiction with a loaded checkpoint it could not apply. The
weak-subjectivity axis, priced: a fresh-syncing node follows the
heaviest chain regardless of any horizon; an attacker able to build a
heavier secret chain longer than ~260k blocks (≈ a year of work above
the honest chain's rate) defeats every non-checkpoint defense in any
design; what changes is only that an established node presented with
such a chain **halts for operator action instead of corrupting**. The
operator-tool framing (steering's, adopted): the console/RPC
`pop_blocks` did not previously *work* past the horizon — it
**appeared** to work and returned a silently-corrupted chain. The
ruling removes no capability; it replaces an unreliable one with a
refusal plus a remedy — **a silent wrong answer becomes a loud
correct one**, the same shape as §4a's `:254` lead exhibit. The
`ARCHIVAL_REORG_DEPTH_BLOCKS = 720` constant stays an **engine
envelope, not consensus** — and its `segment.rs:20` duplicate
collapses to the single source or names its owner in the same change
(delete-the-duplicate).

*Falsifier (Q1c):* the horizon refusal reopens if a node class with
un-pruned archival state is ever minted (deep reverts become
reconstructible), or if the retention design decouples the prune from
the epoch-close hook — either change re-derives this ruling's premise.

### C2-R1b-Q2 — the operator-checkpoint trust surfaces (E1, E2, E5)

**Q2a (uniform wiring — ratified; existence — HELD, deliberately).**
Two questions the first draft fused, split on Rick's direction from
the census thread. **The existence question is held provisional**: the
operator-checkpoint mechanism is a trusted-party override in a
trust-minimised system, and the attack it defends against may have a
strictly better answer in a protocol-level depth bound — a comparison
the census could never pose because "max reorg depth" had no
`file:line` to anchor a row. C2-R0 owns that comparison (named owner,
inserted before R1c); ratifying "the mechanism is kept" now would
either churn or freeze a trusted-party override the network may not
need. **What is ratified now is everything that is right whether or
not the mechanism survives:** *while the mechanism exists*, it is
**wired uniformly across all three public networks** per rule 71 —
both nettype sites (`:254`, `:326`) are deleted, every network loads
`<datadir>/checkpoints.json` at init and reloads on the 600 s path,
and an operator can rehearse a checkpoint override on testnet before
ever touching mainnet (§4a's unreachable-by-construction defect
closes; the gate's allowlist shrinks 8 → 6 in the same change). Scope
fence: this re-homes the **checkpoint mechanism only**; the hard-fork
table selection stays the allowlist's named migration debt.

*Falsifier (Q2a):* the wiring ruling — any future per-network
divergence requires rule 71 §2's named-ratified-loud form; the gate
enforces the default. The held existence question resolves in C2-R0's
comparison; if the mechanism is retired there, the uniform wiring
retires with it at zero additional cost (it is a deletion of two
guards, not an investment).

**Q2b (conflict semantics, ratified separately — rule 82).** Two
distinct conflicts, two distinct verdicts, both ratified explicitly:
(i) **JSON-internal conflict** (same height, different hash) →
`graceful_exit()` = `raise(SIGTERM)`: the daemon **fail-stops**. Kept:
a node holding two contradictory pins for one height has no safe
direction, and datadir write access is already LMDB-corruption
-equivalent — the file adds operator *authority*, not attacker
*access* — so the kill-switch framing adds no new threat position;
the rule-82 obligation is that the exit path names the file, height,
and both hashes before dying (verified or added at build).
(ii) **chain conflict** (a loaded checkpoint contradicts the local
chain) → the rollback target is ratified as
**`saturating_sub(pt.first, 2)`** — review round 2 found the inherited
expression's boundary: a checkpoint at height 1 is loader-accepted,
and unsigned `pt.first − 2` wraps to `UINT64_MAX`, which
`rollback_blockchain_switching` treats as target-above-tip and
**returns immediately — no rollback, while checkpoint loading reports
success**. That is the *third* reports-success-while-doing-nothing
instance in this one mechanism (the `:254` guard, the missing-file
loader, now the wrap) — at three, this stops being a coincidence and
becomes a finding about the mechanism's **whole error-handling
posture**: every edge in the inherited checkpoint machinery resolves
toward reporting success, and R1c should read its nine rows expecting
the same posture rather than treating each instance as local. The
ruling closes this one: targets clamp to 0
(genesis) for checkpoints at heights 1–2, and the wrap case becomes
unrepresentable. The rollback rides the pop machinery and is
therefore **subject to Q1c's watermark refusal**: an operator
checkpoint conflicting below the watermark cannot force a
beyond-floor rollback — the daemon refuses loudly and the remedy is
resync. Stated here because the two rulings compose: E5 hands every
network's operator a pop trigger, and Q1c bounds what any pop —
operator-commanded included — may do.

*Falsifier (Q2b):* the fail-stop reopens on operational evidence of
accidental-conflict kills (a named telemetry signal, not a vibe);
the rollback interaction reopens with Q1c.

**Q2c (the difficulty-checkpoint twin — delete).** `m_difficulty_points`
is **unpopulatable** (the JSON schema carries height+hash only; the
3-arg `add_checkpoint` is its sole writer and nothing calls it with a
difficulty) and its two consumers are an init drift-check that is
structurally dead (empty map ⇒ `{true, 0}` ⇒ the arm never fires) and
a periodic recalculation whose empty-map default degenerates to **a
full-chain difficulty recompute from height 0 once a week** — live
wasted work inherited by accident. The chain, stated so the claim is
checkable (a review read only the init consumer and concluded the
periodic recompute could not fire): `m_diff_recalc_interval` is
`once_a_time_seconds<60*60*24*7>` (`cryptonote_core.h:994`); on-idle
it calls `core::recalculate_difficulties()` (`:1570`) which calls
`Blockchain::recalculate_difficulties()` with its **defaulted
`std::nullopt`** argument (`blockchain.h:354`) — and only then does
the empty map turn `check_difficulty_checkpoints().second` into
`start_height = 0`. The init-time consumer is guarded by
`difficulty_ok` and is indeed structurally dead; the interval caller
is unconditional. Ruled: delete the twin
(map, 3-arg parameter, `check_difficulty_checkpoints`,
`get_difficulty_points`) and retire-or-rescope the recalculation
machinery after enumerating its jobs at build time (a drift-healing
job, if wanted, needs a design with a real trigger, not an empty-map
accident). Behavior-preserving except the removal of the accidental
periodic recompute, which is measured and stated in the build PR.

*Falsifier (Q2c):* difficulty pins may return only via a design round
that names their trust root and populator — the R1a reopening form.

### Q1/Q2 wargame

Asset: the node's chain-selection integrity and its epoch-scoped
archival state. Writers of the pop surface: the switch, the operator
checkpoint rollback, the RPC/console `pop_blocks`, the offline
importer — all covered at the one landing point (Q1c); the E5 file is
the one operator-authority input (Q2b).

| Adversary | Channel | Today | Under the rulings | Direction check |
| --- | --- | --- | --- | --- |
| Majority-hash attacker, shallow (< horizon) | heavier alt chain | switch fires; promotion re-validates; rollback contains invalid bodies | unchanged — Q1a ratifies; cost floor is real PoW above the honest tip | countermeasure (promotion re-validation) sits on the attacker's path; residual churn cost is R1c's subject |
| Majority-hash attacker, deep (> horizon) | heavier secret chain, ~year-scale | pop traverses; epoch re-derivation **silently wrong** | loud refusal at the landing point; operator resyncs | faces the write path all four writers share; converts corruption to halt; the floor is node-local by design (the hazard is this node's data loss) — divergence means some nodes halt loudly where others follow, never a split |
| Operator error: conflicting JSON | datadir file | SIGTERM (undocumented) | same, ratified + named-output obligation (rule 82) | fail-stop on ambiguous pins is the safe direction; authority-not-access priced |
| Malware with datadir write | checkpoint file | could pin a false chain or kill the node | unchanged — datadir write is already LMDB-corruption-equivalent; no new position | the file adds no access an attacker lacks; refusing to ship the mechanism would not remove the position |
| Checkpoint-forced lighter chain | operator pin + K6 arm | switch + discard of heavier demoted chain | ratified with rationale: discard is the flip-flop terminator | the discard faces the oscillation, which is the actual failure mode |
| Testnet operator rehearsing recovery | checkpoints.json on testnet | **structurally impossible** (`:254`/`:326`) | first-class on every network | the rehearsal gap was the rule-71 lead exhibit; closing it is the point |

**Positive check (steering's addition, owed at build):** the
checkpoint-mechanism tests run against **all three** public
`NetworkParams` — the cross-params suite proves there is nothing left
to branch on, where the grep gate only catches someone adding a
branch.

---

## 4c. R1b execution record (built on `feat/c2-r1b-impl`, 2026-09-03)

Phases, in landing order, each red-first where a losing leg exists:

1. **Q2a** — both nettype guards deleted (`:254`'s `return true`
   false-positive and the `:326` init wrapper); `init_default_checkpoints`
   collapsed to one body (per-network DATA only). **Rule-71 allowlist
   8 → 4, exceeding the ratified 8 → 6 deliberately**: the two
   `checkpoints.cpp` no-op-arm entries carried the disposition
   "C2-R1b re-homes or deletes" — leaving them would have left their own
   disposition undischarged. The cross-params suite
   (`checkpoint_uniformity.cpp`) runs identical load + enforcement
   verdicts on all three public networks.
2. **Q2c** — the twin deleted whole: `m_difficulty_points`, its getter,
   `add_checkpoint`'s difficulty arm, `ADD_CHECKPOINT2`,
   `check_difficulty_checkpoints`, `recalculate_difficulties` and the
   weekly interval. Jobs enumerated: the init drift-check was
   structurally dead (empty map ⇒ `{true, 0}`); the periodic job's only
   live effect was the accidental full-chain recompute; the
   drift-healing job, if ever wanted, needs a designed trigger.
3. **Q1c** — the watermark: `note_archival_prune_watermark_epoch`
   (monotonic, wtxn-required, written by the prune before its deletions
   in the same txn) + `get_archival_prune_watermark_epoch` (base default
   0 keeps every test double permissive) + ONE predicate
   (`pop_target_allowed`) consumed by the `pop_block` belt and three
   pre-checks that never re-spell it. **The belt's losing leg was
   observed red first**: the bite test ran against the beltless tree and
   failed with "Actual: false" (the pop completed silently on the no-op
   double) before the enforcement commit turned it green. F-1(a): the
   switch pre-check fails before mutating (fork height vs floor), sets
   the sticky `m_following_degraded`, logs per re-attempt, and surfaces
   as `get_info.following_degraded` (`CORE_RPC_VERSION` 3.26). **RK-5c
   coordination (steering's sequencing ruling):** the field is minted
   here the lane's way — RK-5a landed, RK-5b is the header remainder,
   RK-5c ("get_info, the hub") is where this flag migrates; RK-5c's
   scope carries no existing health slot, so this field is a **named
   input to RK-5c's design**, and its test is value-shaped
   (the flag's transitions, not the wire form) per RK-D9 so the
   migration keeps it. Reset semantics: process-lifetime sticky,
   re-armed on recurrence; alt blocks drop at restart, so a restarted
   node re-degrades exactly when peers re-send the heavier chain —
   self-correcting, not clear-on-restart. F-1(b): a watermark-refused
   checkpoint rollback returns false through
   `Blockchain::update_checkpoints` into the existing
   `core::update_checkpoints → graceful_exit()` fail-stop, with the
   named output at both layers. **F-2**: the exemption is enforced
   structurally — `check_consensus_invariants.sh` [6/6] asserts the
   watermark writer exists, its property key appears exactly twice
   (reader + writer), and NO `revert_*` body references it (anchored on
   the prune watermark's identifiers; the slash-fold watermark is a
   different concept and stays free) — bitten red on a planted
   revert-body reference. **Vector decomposition, recorded as the
   derivation Rick asked for:** the floor quantizes to settlement-epoch
   open heights (SEB = 10,000), so no unit-scale chain can straddle it;
   vectors (ii)/(iii) therefore run against the production predicate at
   the exact boundary (`open`, `open − 1`), the belt is bitten
   separately through `pop_block` itself, and F-2's cross-boundary
   no-revert claim is carried by the [6/6] structural gate plus the
   writer-monotonicity tests — the full SEB-scale flow belongs to
   stressnet territory and is named as such rather than faked.
4. **Q2b** — `saturating_sub(pt.first, 2)` (the wrap unrepresentable),
   conflict messages carry height + both hashes + file + watermark +
   remedy.
5. **Q1b** — `fork_choice` and `alt_window_plan` land in
   `shekyl-difficulty` (49 native tests incl. the u128 hi-word boundary
   and the D5 contiguity refusals), exported beside `lwma1`/`check_hash`
   in `difficulty_ffi.rs` (**no new `from_raw_parts` — the boundary
   ratchet pin is untouched**; both exports take scalars/structs by
   value). C++ consumes the verdict at the admission site (the discard
   flag stays orchestration keyed on the checkpoint arm) and performs
   the fetches `alt_window_plan` names — both regimes now come from one
   function, and the old reverse-fill branch is gone. Shared vectors
   `docs/test_vectors/FORK_CHOICE_V1.json`, pinned per rule 30, with
   two consumers: `fork_choice_vectors.rs` (native) and
   `fork_choice_vectors.cpp` (end-to-end through the FFI).

Bookkeeping: census rows K5/K6/K7/K8/D5/D6/E1/E2/E5 → bucket 2 (the
E-rows carrying the **held-existence** condition in their own text),
counts 86/25/5/55; the watermark names itself in the CSR store map
(minted after the 18-row map landed) **and in `docs/LMDB_SCHEMA.md`**
(properties table + the v12 version-history section); the
`RETENTION_HORIZON_BLOCKS` rename rides FOLLOWUPS per Rick.
**Corrected claim, owned:** an earlier revision of this record said
"`LMDB_SCHEMA.md` does not exist" — a wrong-instrument negative
(`grep -l LMDB_SCHEMA docs/` lists files *containing* the string, and
the doc does not name itself; `check_lmdb_schema_coverage.py` reads it
and failed CI the moment VERSION moved). The truncated-listing rule's
fourth instrument: a containment grep cannot prove a file's absence —
`ls` the path.

**Copilot round 3 (#603, all five findings suppressed-but-valid, each
addressed):** the substantive one — a watermark-refused switch set
`bvc.m_verifivation_failed`, and both P2P receive paths respond to
that flag by dropping and scoring the peer, so a degraded node would
have punished every honest peer advertising the heavier chain and
isolated itself onto its own fork. **The refusal is a local retention
limitation, not block invalidity**: the pre-check now lives in the one
caller (`handle_alternative_block`'s switch arm — still before any
mutation, same predicate), the block stays in the alt store, `bvc`
carries no failure, and the peer is kept; the pop belt still backstops
any unchecked path. Value-shaped coverage the PR had promised and not
delivered now exists: core test `gen_reorg_watermark_refused_switch`
(fixed difficulty 1; watermark armed by callback; a strictly-heavier
alt fork below the floor) pins the false→true transition, stickiness
across a second refusal, and the unmoved tip — observed red on the
pre-fix form at exactly the `m_verifivation_failed` axis. Lesser
findings: the [6/6] writer-count floor (`>= 2`) became an equality so
a third call site turns the gate red instead of passing; the `-5`
window code joined `difficulty_ffi.rs`'s module-level wire-stable
table; this doc's header no longer says the implementation "lands on
PR #600". Same round: `origin/dev` merged (CHANGELOG both-sides-add
resolved keeping both families; dev's CEN-M8 hash-gated skip is
disjoint from every R1b region).

## 5. R1c scope (alt admission + acceptance topology) — not yet ruled

### 5.1 Threat framing

**The corrected Qubic facts lead this framing, sign first: the
correction cuts toward MORE risk, not less.** The measured campaign
averaged 23.38% of Monero's hashrate — 28.33% during withholding
periods — and inside that minority average, short intervals **briefly
exceeded 50%** (daily/weekly aggregates never reached 51%; no stable
majority was held; arXiv 2512.01437, primary-fetched 2026-09-03). The
campaign's mechanism was **withholding**: selfish mining produces
multi-block reorgs at sub-majority by construction. An 18-block reorg
(height 3,499,659, 118 transactions, ~36 minutes, 2025-09-14/15 — the
deepest instance in this round's corpus; multi-outlet secondary record)
is attributed to that campaign's withheld chain. Which mechanism
produced it — brief majority or sub-majority withholding — is not
established by the source, **and does not need to be: both defeat an
aggregate-calibrated rule.** A depth rule calibrated on aggregate
hashrate share is therefore **blind twice over**: it misses the brief
majority windows inside a minority average, and it misses that the
withholding mechanism does not need majority at all. **Rick's binding
design constraint for this round (2026-09-04): a depth rule that
decides in seconds must be designed against intervals, not averages.**
GAP-1 and GAP-2 (census §12) deliver this round's inherited questions
with that evidence attached.

The constraint joins the row set at its center: **CEN-K4's
prevalidate-only admission deferral is the surface a brief-majority
attacker stages through** — admission is deliberately cheap (version,
attestation, timestamp, checkpoint, PoW-at-alt-difficulty, prevalidate
only), so everything an interval attacker needs to position a withheld
chain is bought at the cheap tier, and the expensive tier
(`validate_miner_transaction`, `check_tx_inputs`, the curve-root
check) is paid only at promotion — by the *victim*, during the seconds
the rule gets to decide in.

### 5.2 Scope and obligations

**R1c now runs after C2-R0** (§1) and inherits its re-scoping note —
C2-R0's stated deliverable is naming which of these nine rows a
protocol-level depth rule affects. The census-wide line re-anchor
stays this round's obligation at R1c close (C2-R0 is docs-and-schema
only and moves no line numbers) — and that re-anchor pass now carries a
second leg: **a dangling-anchor sweep of the census's §-citations into
this doc**, because the links gate resolves files, not anchors (the
consumed-§5-heading defect survived to dev exactly that way — a
collapsed observable no gate can currently see).

Rows: CEN-K1, K2, K3, K4, K9, K10, A1, A2, A4. Banked wargame seeds:
near-tip cycle cost (a 1-block fork needs ~2 blocks of real PoW to force a
full pop-and-restore; victim churn per attacker block); `build_alt_chain`
re-walks and re-parses the **entire** alt ancestry on every admission —
cheap deep forks (historic difficulty near height 1 is trivial, E2 vacuous)
cost the victim quadratic CPU and unbounded LMDB within an uptime, floored
only by drop-at-restart (`--keep-alt-blocks` opt-in,
`cryptonote_core.cpp:655`); K10's `verification_impossible` pool residue as
the storage cost of a failed switch. Check-in leans: K2 orchestration
(store-rebuild integrity asserts), K4 composition-is-call-ordering (member
rules already have owners), nothing new crosses.

## 6. Round log

- 2026-09-02 — Ground read at `bf317111f`; check-in with steering
  (shekyl-core-00): pin, per-row rule-vs-orchestration read, order proposal.
  Steering adopted the decision-grouped structure (§1) and withdrew the
  brief's E1 "likely crosses" hypothesis.
- 2026-09-02 — R1a proposal reviewed by steering; load-bearing claims
  independently re-verified; approved for ratification with one fix (the
  reopening trigger pointed at a tolerance that does not exist — replaced
  with the §3.5 interim absolute).
- 2026-09-02 — Rick ratified C2-R1a-Q1 and the CEN-G8 retirement (both
  explicit); raised the two-checkpoint-mechanisms finding (§4a) and
  directed the network-uniformity principle be minted as a standing rule
  first (rule 71) with R1b citing it; implementation + rule + gate landed
  in the R1a PR (execution record §3.8).
- 2026-09-02 — R1a merged by Rick (#596 → `4b9807c5e`; 56 files,
  +924/−1012 vs its dev parent) after five Copilot rounds (§3.8 carries
  each round's corrections); branch archive-tagged
  (`archive/c2-r1a-checkpoint-fastsync-2026-09-02`) and deleted, lane
  moved to `wt-c2r1b`/`feat/c2-r1b-fork-choice`. Steering sharpened
  §4a's lead exhibit: `:254`'s `return true` is a silent **false
  positive**, not a skip.
- 2026-09-02 — §4b proposed: Q1a fork-choice ratification with the
  discard-asymmetry rationale, Q1b crossings (fork-choice predicate +
  D5 selection arithmetic to `shekyl-difficulty`; E1 ruled no-crossing
  with DRS/R8 as named owner), Q1c the horizon refusal at the pop
  landing point (grounded on the enumerated failure shapes: loud
  bond-record FATALs, tolerant bit-removal, silent budget re-derivation
  past the prune horizon), Q2a uniform wiring (both sites, all
  networks), Q2b the two conflict semantics ratified separately
  (SIGTERM fail-stop; rollback subject to Q1c), Q2c the
  difficulty-twin deletion (with the accidental periodic full-chain
  recompute enumerated).
- 2026-09-02 — PR #600 opened at Rick's request (proposal-only;
  implementation lands on it after ratification). Census-direction
  check-in answered by steering: **C2-R0 (negative-space round) inserts
  before R1c** — the census cannot mint rows for rules with no
  `file:line`, and its finding #1 is maximum reorg depth. §4b amended
  accordingly: Q1c scoped as a storage-recoverability bound ("a
  finality rule wearing storage clothes" — the security depth bound is
  C2-R0's, strictly tighter, composing not competing) with the landing
  point stated by property; **Q2's existence question split out and
  HELD** pending C2-R0's mechanism-vs-depth-bound comparison, with the
  wiring/conflict/twin rulings ratifiable now (right regardless of the
  mechanism's survival, and the wiring retires at zero cost if the
  mechanism does); E1's reopen trigger re-checked against the landed
  CSR (#595 — zero checkpoint rows; not live). C2-R0 cited as briefed,
  pending dispatch, not yet tree-landed.
- 2026-09-03 — Copilot rounds 1–2 on #600 (all eight findings valid or
  strengthening; the slack dissolved into the prune's boundary
  function, then the tip-derived floor replaced by the persisted
  monotonic watermark; the `pt.first − 2` wrap closed as the third
  reports-success instance — named as a POSTURE finding for R1c; the
  caller-less no-arg `pop_block` overload exposed and ruled deleted).
  Steering re-verified the watermark's one-writer premise and
  corrected the round's own "no new subjectivity" sentence: the floor
  is **node-local by design** — durability, not uniformity, is the
  safety property.
- 2026-09-03 — Built (§4c): all six rulings implemented red-first on
  `feat/c2-r1b-impl`; the belt's losing leg observed red before
  enforcement; every gate green (rule-71 at allowlist 4, invariants
  6/6, fmt/clippy workspace-wide, crate + FFI + vector suites).
- 2026-09-03 — **RATIFIED by Rick** as amended at `ad72e1bc9`: every
  new source claim re-verified by him (the wrap at `:6725`, the
  above-tip `return true` at `:1351`, the weekly-recompute chain, the
  zero-caller overload). Conditions F-1 (refused-pop daemon semantics
  on the switch and checkpoint-conflict paths) and F-2 (watermark
  exempt from pop reversal + three named red vectors) — both landed
  above, neither needing re-signature (additions within the ratified
  design). **Two retractions logged under Rick's name at his
  instruction:** (1) the walk-down hole was present in the form he
  ratified ("derived from `max_claim_age_w` minus named slack" is a
  pop-time derivation from current state) just as in the first draft —
  the watermark closes it; (2) his R1b verification repeated the
  no-arg overload's header comment ("the add-failure undo") as fact
  without running the caller search — the same
  documentation-is-not-verification failure the round twice caught in
  others' prose. The record shows the reviewer's misses the same way
  it shows everyone else's. Minor tracked: the
  `RETENTION_HORIZON_BLOCKS` rename row rides the build PR's FOLLOWUPS
  edit (hygiene under the watermark form; the name cost one wrong
  ruling).
- 2026-09-03 — Copilot round 3 on #603 (five suppressed findings, all
  valid, all addressed — record in §4c): the refused-switch
  peer-punishment defect fixed (refusal no longer travels
  `m_verifivation_failed`; block kept as alternative, peer kept), the
  promised `following_degraded` value test built and observed
  red-first (`gen_reorg_watermark_refused_switch`), the [6/6]
  writer-count floor tightened to an equality, the `-5` code added to
  the FFI error table, the stale "lands on PR #600" header corrected.
  `origin/dev` merged in the same round (CHANGELOG both-families
  resolution; dev's CEN-M8 hash-gate disjoint from R1b's regions).
- 2026-09-03 — Copilot round 4 on #603 (three findings, all valid, all
  addressed): the Q2b saturated-to-zero rollback target aborted on the
  can't-pop-genesis guard for a height-1/2 checkpoint conflict — the
  target is now floored at the genesis-only chain (DB height 1), and a
  conflict AT genesis fail-stops as unresolvable instead of reporting a
  no-op rollback as success (the shape's fourth instance); the
  checkpoint walk now stops after an applied rollback, because the
  height-ordered later entries would be tested against the stale
  pre-rollback height and read past the new tip; the C++ RPC header's
  prose copy of `CORE_RPC_VERSION` ("3.25") replaced with a
  number-free pointer — a prose copy of a moving constant only goes
  stale. Core test `gen_checkpoint_conflict_rollback` pins the
  completed rollback with a second conflicting checkpoint present,
  observed red-first ("Cannot pop the genesis block" escaping the
  walk).
