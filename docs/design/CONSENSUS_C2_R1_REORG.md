# C2-R1 — Reorg / alt-chain / checkpoints design round

**Status:** **OPEN — R1a RULED and executed (2026-09-02); R1b next.**
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

2 + 9 + 9 = 20 ✓. One PR per sub-round, ratify-then-build, sequenced
R1a → R1b → R1c.

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
  into `ci/grep-gates`, allowlist seeded with the 6 surviving public-
  nettype branches (annotated with owners), and **bitten in both
  directions before trust**: a planted `if (m_nettype == MAINNET)` in
  scope went red (unlisted-hit arm), a mutated allowlisted branch went
  red (stale-entry arm), restore green.
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

- `cryptonote_core.cpp:332` wraps the **entire** operator-checkpoint init
  block — `init_default_checkpoints`, `set_checkpoints`, **and**
  `set_checkpoints_file_path` — in `if (m_nettype == MAINNET)`. Off
  mainnet, `m_checkpoints_path` stays `""`,
  `boost::filesystem::exists("")` is false, and the JSON loader
  (`checkpoints.cpp:195`) silently no-ops. **The operator-override path —
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
`cryptonote_core/ + checkpoints/ + blockchain_db/`, allowlist seeded at 6
and annotated. R1b therefore owes, citing rule 71 rather than re-deriving
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

## 5. R1c scope (alt admission + acceptance topology) — not yet ruled

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
