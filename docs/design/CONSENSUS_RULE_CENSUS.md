# Consensus-rule census — merged instrument (C1)

**Status:** OPEN — the single live consensus-rule census. Produced by the C1
reconciliation pass (2026-08-31) over three independent enumerations of the
same surface plus one steering-side evidence-archaeology payload. This is the
specification input for the all-Rust consensus rewrite (ruled 2026-08-30/31:
census precedes rewrite; C++ is a differential-test oracle only for rules
ratified on record — **extended 2026-09-02 (CSR-3a): ratification is necessary
but not sufficient.** A bucket records that a rule is *specified and ratified*,
never that the C++ *implements* the spec it was ratified against. CEN-L11 was the
counterexample — bucket 1, ratified, and its implementation silently omitted an
accepted output from the curve tree. Oracle status therefore requires **both**
ratification **and** an **affirmative conformance record** for the row — a check
that the C++ implements the spec it was ratified against. **Absence of a recorded
divergence is not conformance:** it means *unreviewed*, and unreviewed rows are
regression-only. See [`CONSENSUS_STORE_RECONCILIATION.md`](CONSENSUS_STORE_RECONCILIATION.md)
§5.4.1 for the three states and the exception register. **DRS-P0f's row
coverage is complete over the 2026-09-02 set**, not the live one (P0f is the per-row conformance review
— *not* P0d, which is Digest v0): the **102** bucket-1/2 rows that existed on
2026-09-02 are disposed — 99 CHECKED-CONFORMANT, 1 DIVERGENT (CEN-B5's rule-71
FAKECHAIN skip, census R9), 2 failed closed (CEN-L8; CEN-I12, split anchor
source). **The set has since grown:** C2-R1b promoted nine rows into bucket 2 on
2026-09-03, so the live bucket-1/2 count is **111** and those nine are
UNREVIEWED until P0f reviews them. **Both S-graded findings are fixed and re-verified** — the S0 by
PR #602 (M8/G4/J26 promoted) and the S1 by PR #604 (CEN-D2/D1 promoted); **CEN-L11/L12 promoted at PR #609's merged fix** (2026-09-04); every other row is UNREVIEWED. Bucket-4 rows record
questions, never answers; the §10
queue is the design-round program that answers them.
**Pinned sha:** `ab3cc98e6eb73db2b309730ccc9853ba4ea95e7d` (`dev` tip,
2026-08-31 — the merge commit of PR #583). Inputs were read at
`8ba1aae3dbd1e3b03504d5d27c0471bb67f11b9d` / `0e6d340e`; `git diff
8ba1aae3d ab3cc98e6 --name-only` — a diff between two pinned commits,
immutable history that no later work (this reconciliation included) can
change — shows exactly six changed files, all docs (the three census
documents, at that sha still under `docs/design/`;
`IMPLEMENTATION_INDEX.md`; `FOLLOWUPS.md`; `CHANGELOG.md`), so every code
and non-census-doc `file:line` read at `8ba1aae3d` is byte-identical at
this pin. Additionally re-read at this pin:
every site a merged row **adds** relative to its CEN source (all minted and
split rows, every RC-sourced site appended to a CEN row), every Appendix-A
pointer folded in §8, and every pointer into the three changed non-census
files (re-located line numbers recorded in place).
**Identifier family:** `CEN-` is canonical (ruled in the C1 dispatch). Merged
rows keep their `CEN-` ids; rows minted during the merge continue each
subsystem's numbering and carry an `[m]` marker in the notes; rows split
during the merge take a letter suffix (`CEN-D1b`) per the registered
`CEN-<letter><n>[letter]` form. Every `RC-` id and Survey-A `U-`/`L-` item
resolves through the §9 accounting table; no input id vanishes silently.
**Supersedes** (archived per rule 95 / index §8 in the same commit, content
retained as the independent-walk records): the two superseded walks moved to
`docs/completed/` as CLOSED-as-record —
[`CONSENSUS_RULE_CENSUS_2.md`](../completed/CONSENSUS_RULE_CENSUS_2.md)
(`RC-`, 181 rows) and
[`CONSENSUS_RULE_CENSUS_3.md`](../completed/CONSENSUS_RULE_CENSUS_3.md)
(`CEN-`, 161 rows); Survey A
([`CONSENSUS_RULE_CENSUS_1.md`](CONSENSUS_RULE_CENSUS_1.md)) stays in
`docs/design/` as a mixed doc — its census content is closed but its §6
L-items are owned open residue.
**Cross-reference (CSR-6, added 2026-09-01).** The daemon chain-store program
([`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md), `DRS-*`) partitions the same
files this census enumerates — by **DB call surface** where this census cuts by
**rule** — and until 2026-09-01 neither document referenced the other.
**18 rows here are enforced inside `src/blockchain_db/`** (7 bucket-1, 1
bucket-3, 10 bucket-4), and **§10's R8 batch is the same decision as that
program's schema design**: R8 is the ruling instrument, the DRS surface map its
input (CSR-1). Rick's **2026-09-01 countermand** — the inherited C++ is not a
base; a complete rewrite gates release — vindicates this census's oracle clause
and propagates it outward. **The clause was then extended, not merely
propagated (CSR-3a, 2026-09-02):** CEN-L11 showed ratification alone is
insufficient, so the header above now carries the conformance condition too. Map, blast radius and work items:
[`CONSENSUS_STORE_RECONCILIATION.md`](CONSENSUS_STORE_RECONCILIATION.md).

Survey A's L-items (Levin/p2p wire) are **out of the consensus census**:
requirements input to the P2P protocol redesign lane (ruled 2026-08-31);
their accounting rows in §9 point there.
**Decision authority:** the census enumerates; it does not rule. The C1 pass
reconciled *walks*, it did not rule any bucket-4 question.
**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
longevity work under priority 3, unchanged from the inputs — a rewrite
cannot take inherited-but-unexamined C++ as its specification
([`16-architectural-inheritance`](../../.cursor/rules/16-architectural-inheritance.mdc),
[`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc)). An
unlisted rule is ratified by silence; the census exists to close that
failure mode. It changes no code.

---

## 1. Inputs and merge method

Four inputs, equal standing, every pointer re-verified before use:

1. **Survey A** (`CONSENSUS_RULE_CENSUS_1.md`, read at `0e6d340e`) — directed
   survey: buckets S/R/D/U, items U-1…U-9 (consensus) and L-1…L-6
   (Levin/p2p wire), observations O-1…O-4.
2. **RC walk** (`CONSENSUS_RULE_CENSUS_2.md`, read at `8ba1aae3d`) — 181 rows
   RC-1…RC-155, RC-157…RC-182 (RC-156 never issued), 48 validation sites,
   17-item decision log.
3. **CEN walk** (`CONSENSUS_RULE_CENSUS_3.md`, read at `8ba1aae3d`) — 161
   rows CEN-A1…CEN-M11, 97-function frontier, seven-re-reader verified.
4. **Evidence-archaeology payload** (steering-side, embedded in the C1
   dispatch) — ratification records located for rules the walkers marked
   record-less, plus enforcement-status caveats and three broken-pointer
   corrections. Folded item-by-item in §8.

**Merge procedure (as ruled in the C1 dispatch).** The merged row set is
built from CEN. RC was then walked row-by-row: same rule ⇒ sites/notes
merged into the CEN row; RC-only rule ⇒ re-verified at the pin and a CEN id
minted; contradiction ⇒ the disagreement protocol below. Survey A's U-items
and the Appendix-A payload were walked the same way.

**Disagreement protocol (as ruled).** *Factual* disagreements (what the code
does) were settled by reading the tree at the pin — ground truth wins, and
the losing text is corrected with a note (§7 logs each). *Judgment*
disagreements (what counts as "ratified") were settled by the §2
evidence-class bar — never by picking a side.

**Bucket-3 posture (reconciled; the walks disagreed 16-vs-0).** RC carried
16 bucket-3 rows; CEN carried zero on principle ("examined-for-deletion
rules have been deleted; nothing live carries that disposition"). The merged
bar: bucket 3 requires a recorded disposition that **names the subject**.
Rule 60's text names ring/mixin residue and commands "delete the dead
branch" for Monero-era `hf_version` dispatch — two merged rows meet that
bar (CEN-H24, CEN-L15). Everything else RC had at 3 either merged into a
host row's notes, moved to the §5 dead-surface record, or sits at bucket 4
with a *rule-60 deletion candidate* note carrying RC's position. Whether the
hardfork **machinery** (as opposed to individual dead branches) is deleted
or redesigned is the §10 R4 round's call, not the census's.

**Stale-figure corrections.** The C1 dispatch (and CEN's own header) cite
RC at 167 rows and an accounting range "RC-1…168"; RC's final landed form
is **181** rows (the miner-tx economics split and the DB-only connect
FATALS were added in-PR after those snapshots). Ground truth is the
document at the pin; §9 accounts for all of RC-1…RC-182 and explains
161-vs-181 row by row.

---

## 2. The evidence-class column (the unified bucket-2 bar)

The input walks disagreed on bucket 2 by an order of magnitude (RC 6, CEN
23). The gap was the *bar*, not the facts. The merged instrument replaces
the binary "bucket 2" judgment with a recorded class per row:

| Class | Meaning | Bucket it implies |
| --- | --- | --- |
| `spec` | Bucket-1 rows: Shekyl-designed, written spec is the evidence | 1 |
| `ratified` | A design round / decision-log entry examined the rule and kept it, with rationale (pointer required) | **2** |
| `ratified-premise-refuted` | A ratification exists but its factual premise is refuted at the tree (held only CEN-C2, which C2-R3 re-ratified on fresh ground into bucket 2 — the class is currently empty) | **4** |
| `examined-disposition` | A review examined it on one path (e.g. the `DAEMON_SUBMIT_VERDICT.md` §8 submit-path matrix) without a full ratification; the row states which path | **4** |
| `KAT-port` | Moved to Rust pinned by vectors. A seal is not a ratification; the right-for-Shekyl question is open | **4** |
| `pinned-not-re-derived` | The value is frozen and documented but inherited without derivation | **4** |
| `none` | Bucket 4 proper — no locatable record | **4** |
| `—` | Bucket-3 rows (recorded deletion disposition; class column not applicable) | 3 |

Bucket assignment is then mechanical. A design round that rules a bucket-4
row with a non-`none` class starts from that recorded partial examination
instead of from zero. Under this bar, nine CEN bucket-2 rows demoted to 4
(C2, F6, G6, H1, H3, H11, K8, M3, M4 — each keeps its class), one CEN
bucket-4 row promoted to 1 on located evidence (H5), and two rows split
where components landed in different buckets (D1/D1b, F14/F14b). §9 lists
every changed row.

---

## 3. Denominator (the completion claim over the merged set)

| Quantity | Count |
| --- | ---: |
| Entry points | 4 |
| Validation-site union (§3.3) | 98 functions |
| Rules (rows in §4) | **171** |
| — consensus-flagged | 162 |
| — policy-flagged | 9 |
| Bucket 1 (Shekyl-specific, spec'd) | 86 |
| Bucket 2 (inherited, ratified on record) | 25 |
| Bucket 3 (deletion disposition recorded or executed) | 5 |
| Bucket 4 (inherited, not ratified — classes recorded) | 55 |

Sum check: `86 + 25 + 5 + 55 = 171 = 162 + 9`. Merged set = 161 CEN rows
+ 8 minted (`CEN-A7, B6, B7, F20, F21, H23, H24, L15`) + 2 split
(`CEN-D1b, F14b`). Bucket-4 class split: 4 `examined-disposition`
+ 2 `KAT-port` + 3 `pinned-not-re-derived` + 46 `none` = 55 (the C1-era
split additionally held 1 `ratified-premise-refuted` + 56 `none`;
C2-R3 ruled CEN-C2 and CEN-C3 into bucket 2, class `ratified` — §7.15;
C2-R1a ruled CEN-E3/E4 removed-and-executed and retired the bucket-1
belt CEN-G8, all three now bucket 3 — the bucket-3 label widens to cover
executed removals, incl. the first retired Shekyl-authored row).

Reproducible counts (run against this file):

```sh
f=docs/design/CONSENSUS_RULE_CENSUS.md
grep -c '^| CEN-' "$f"                                                          # rows = 171
grep '^| CEN-' "$f" | awk -F'|' '{gsub(/ /,"",$5); print $5}' | sort | uniq -c  # C/P
grep '^| CEN-' "$f" | awk -F'|' '{gsub(/ /,"",$6); print $6}' | sort | uniq -c  # buckets
grep '^| CEN-' "$f" | awk -F'|' '{gsub(/ /,"",$7); print $7}' | sort | uniq -c  # classes
```

### 3.1 Per-subsystem breakdown

| Subsystem | Rows | B1 | B2 | B3 | B4 | Policy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A topology | 7 | 1 | 0 | 0 | 6 | 0 |
| B header / version / attestation / root | 7 | 2 | 1 | 0 | 4 | 0 |
| C timestamps | 3 | 1 | 2 | 0 | 0 | 0 |
| D PoW / difficulty | 8 | 4 | 2 | 0 | 2 | 0 |
| E checkpoints / fast-sync | 5 | 0 | 3 | 2 | 0 | 0 |
| F miner tx / emission | 22 | 13 | 3 | 0 | 6 | 0 |
| G block body (connect) | 14 | 7 | 0 | 1 | 6 | 0 |
| H tx non-input consensus | 24 | 9 | 5 | 1 | 9 | 0 |
| I FCMP++ inputs / PQC | 18 | 14 | 4 | 0 | 0 | 0 |
| J archival tx families | 26 | 26 | 0 | 0 | 0 | 0 |
| K reorg / alt chains | 11 | 1 | 4 | 0 | 6 | 0 |
| L storage layer | 15 | 6 | 0 | 1 | 8 | 0 |
| M mempool admission | 11 | 2 | 1 | 0 | 8 | 9 |
| **Total** | **171** | **86** | **25** | **5** | **55** | **9** |

### 3.2 Inverse spot-check (union of both walks' tables; all six MUST be present)

Both input censuses independently chose the same six subjects; the union is
therefore the same set, now resolved to merged ids:

| Expected subject | Merged row(s) | Was (RC / CEN) |
| --- | --- | --- |
| FCMP++ membership-proof verification | **CEN-I15** | RC-94 / CEN-I15 |
| PQC transaction auth | **CEN-I16–I18** | RC-108 / CEN-I16–I18 |
| Timestamp-median rule | **CEN-C2** | RC-31 / CEN-C2 |
| `validate_miner_transaction` emission check | **CEN-F13–F18** | RC-47 / CEN-F13–F18 |
| Key-image double-spend | **CEN-I7** (verify) + **CEN-L1** (connect) + **CEN-H10/I5** (intra-tx) | RC-85 + RC-144 / CEN-I7 + CEN-L1 |
| PoW check | **CEN-D1/D1b/D2** | RC-24 / CEN-D1/D2 |

### 3.3 Validation-site union

The union of the two walks' frontiers is CEN's 97-function visited list
(`CONSENSUS_RULE_CENSUS_3.md` §1.3, retained verbatim in the archived doc)
**plus one function RC walked that CEN's list does not name**:
`check_hash` (`src/cryptonote_basic/difficulty.cpp:64–86`, now a marshaling
wrapper over the Rust `shekyl_difficulty_check_hash`) — 98 functions. Every
one of RC's 48 listed sites maps into that union (RC's FFI-verdict entries
42–48 correspond to CEN's named Rust crates). CEN's frontier is strictly
deeper on `checkpoints.cpp` internals, `HardFork` internals, and the Rust
verdict crates it crossed into.

### 3.4 FFI scope statement (where the walk stops at a Rust verdict body)

| FFI verdict surface | Rows | Interior enumerated? | Spec it is enumerated/pinned against |
| --- | --- | --- | --- |
| `shekyl_fcmp_verify` | CEN-I15, J21, J26 | **No** (boundary read; proof math not walked). The §7.13 y-normalization question is open | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §7; [`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) |
| `shekyl_pqc_verify` | CEN-I18 | **No** (boundary read; pinned KATs) | [`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md); [`PQC_MULTISIG.md`](../PQC_MULTISIG.md) |
| `shekyl-economics` (reward, split, burn, release) | CEN-F13–F17, F20 | **Yes** (CEN read `emission.rs`, `release.rs`; 81-vector cross-language KAT) | `config/economics_params.json`; [`ECONOMY_EXPLAINED.md`](../ECONOMY_EXPLAINED.md) |
| `shekyl-difficulty` (LWMA-1, `check_hash`, timestamp rule) | CEN-D1b, D4, C1, C2, C3 | **Yes** (`lwma1.rs` is a step-annotated transcription of the spec; `check_hash_vectors.rs`; `timestamp.rs` `check_timestamp_rule` is **production-live** through `shekyl_difficulty_check_timestamp_rule` since the C2-R3 crossing — the C++ validator's `check_block_timestamp` is a marshaling shim; vectors `MTP_BOUNDARY_V1.json` pin it natively and end-to-end) | [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) §5.3; [`CONSENSUS_C2_R3_TIMESTAMPS.md`](../completed/CONSENSUS_C2_R3_TIMESTAMPS.md) §4.3/§7 |
| `shekyl-pow-randomx` (hash, seed epoch) | CEN-D2, D3 | **Yes** (`seed_epoch.rs` read) | [`RANDOMX_V2_RUST.md`](RANDOMX_V2_RUST.md) :393, :790–823; [`RANDOMX_V2_PLAN.md`](RANDOMX_V2_PLAN.md) |
| `shekyl-archival-retention` (bond, serve-credit, admission, emission, settlement) | CEN-J*, L7–L10 | **Partially** (CEN read bond_post, serve_credit_decisions, admission, failure_window, emission verify; RC did not cross) | gate-2 / [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) / E3 / [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md) / [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) |
| `shekyl-ct-balance` | CEN-H17, H18 | **Yes** (single-sourced with the builder) | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3 |

The rewrite consumes this table as its oracle-scope map: where the interior
is not enumerated, the named spec — not the C++ or the FFI behavior — is
the specification of record.

### 3.5 Main-chain vs alt-chain rule application (carried from RC §1.2)

| Check | Main (`blockchain.cpp:5810`, `handle_block_to_main_chain`) | Alt admission (`:2278`, `handle_alternative_block`) | On promotion |
| --- | --- | --- | --- |
| Hardfork | `HardFork::check` (current) | `check_for_height` (ideal at height) | re-run main |
| Attestation | yes | yes | re-run main |
| Timestamp FTL | yes (Rust rule via FFI; C++ shim `:5612`) | **yes** (same rule fn via `:2381` — C2-R3-Q3 closed the was-missing bound) | re-run main |
| Timestamp median | yes (strict, newest 11) | yes (strict, newest 11 after `:2376` truncation — was the whole alt chain; C2-R3-Q1a) | re-run main |
| PoW | RandomX v2 + `check_hash` | `get_altblock_longhash` + alt LWMA-1 | re-run main |
| `prevalidate_miner_transaction` | yes | yes | re-run main |
| `validate_miner_transaction` | yes | **no** | re-run main |
| `check_tx_inputs` / FCMP / PQC | yes (FCMP skippable if pool-cached) | **no** — txs pooled as `relay_method::block` | re-run main |
| `ver_non_input_consensus` | on supplement | on supplement | re-run main |
| Weight / reward / curve-tree root | yes | weight approximated; may zero | re-run main |
| Reorg trigger | n/a | cum. difficulty **or** checkpoint | — |

Alt **admission** is a subset; consensus at connect is the main-chain path,
which promotion re-enters (CEN-K5). Rules enforced only at alt admission
stay in the denominator: they decide what is stored as alt and what can
trigger a reorg before promotion. This table is the R1 round's starting
exhibit (§10).

---

## 4. Rows

Columns: **CEN-id** | behavioral statement | enforcement site(s)
(`blockchain.cpp` under `src/cryptonote_core/` unless another file is named)
| **C**onsensus / **P**olicy | bucket | evidence class (§2) | evidence |
notes. Sites are `file:line` at the pinned sha (see the header's
verification statement). `RC-nn ⇒` in notes records the RC rows merged in;
`[m]` marks a row minted in the C1 merge; a letter-suffixed id is a C1
split.

### 4.A Acceptance topology

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-A1 | A block whose hash is already known (main, alt, or invalid set) is rejected with `m_already_exists` | 6637 (`have_block` :3094 → `have_block_unlocked` :3062) | C | 4 | none | — | RC-4 ⇒ merged. DB belt is CEN-L3 |
| CEN-A2 | A block whose `prev_id` equals the current tail goes to the main-chain path; any other goes to the alternative path; main-chain connect re-checks `prev_id == top_hash` and fails closed | 6645–6655, 5705–5711 | C | 4 | none | — | RC-5 ⇒ merged (fail-closed re-check site added from RC) |
| CEN-A3 | The witness-less 2-arg `add_new_block` refuses any block with a non-empty `attestation_root` (a caller dropped the credit-wire witness) | 6619 | C | 1 | spec | [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) §3 | RC-11 ⇒ merged. Hard guard until the miner-local path is rewired (FOLLOWUPS) |
| CEN-A4 | A block whose parent is in neither main nor alt storage is marked orphaned and **not stored**; the p2p layer must re-request ancestry | 2511–2518 | C | 4 | none | — | RC-6 ⇒ merged |
| CEN-A5 | An incoming block blob larger than the current cumulative weight limit + `BLOCK_SIZE_SANITY_LEEWAY` (100) is rejected before parse | cryptonote_core.cpp:1408–1419, 1342 | C | 4 | none | — | RC-1 ⇒ merged. The 100 is a local `#define`, not `config/`; pre-parse approximation of CEN-G6b |
| CEN-A6 | A block blob that fails `parse_and_validate_block_from_blob` is rejected | cryptonote_core.cpp:1355; parse cryptonote_format_utils.cpp:1457–1470 | C | 4 | none | — | RC-2 ⇒ merged. Wire-format boundary; the parse itself is [`BLOCK_TX_WIRE_FORMAT_PORT.md`](BLOCK_TX_WIRE_FORMAT_PORT.md)'s census subject |
| CEN-A7 | `tx_hashes.size() > CRYPTONOTE_MAX_TX_PER_BLOCK` (`0x10000000` = 2^28) fails block (de)serialization — a structural bound enforced inside the serializer | src/cryptonote_basic/cryptonote_basic.h:902–903 | C | 4 | none | — | [m] RC-3 ⇒ minted. Bound frozen in the §10 bounds table (`GENESIS_TX_WIRE_FORMAT.md` :803 block-level bounds) but the *value* has no derivation record |

### 4.B Block header: version, attestation, curve-tree root

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-B1 | Block `major_version` must equal the voted current version — with the shipped single-entry table `{v1, h1, threshold 0}` on all three networks this is exactly `major_version == 1`. Alt path checks against `get_ideal_version(height)` instead of the voted current version (diverges only if vote and ideal disagree; the one-row table makes them equal) | 5727 (main, `HardFork::check` → `do_check` src/cryptonote_basic/hardfork.cpp:109); 2242 (alt, `check_for_height` :128); table src/hardforks/hardforks.cpp:35–50 | C | 2 | ratified | rule [`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc) ("Shekyl's minimum hard fork version is 1"); hardforks.cpp:34 "Rebooted chain: all features active from genesis." | RC-8, RC-10, RC-162 ⇒ merged. The table's `time` payload `1341378000` is a CryptoNote-era unix stamp: unexamined residue on a ratified shape (RC-162 note carried) |
| CEN-B2 | Block `minor_version` is effectively unconstrained: `do_check` requires `vote ≥ current`, but the vote normalization (`minor 0` reads as 1) and `current == 1` make the predicate unfailable — any `minor_version` is accepted | src/cryptonote_basic/hardfork.cpp:41–50, 109–113 | C | 4 | none | — | RC-9 ⇒ merged with correction: RC stated the predicate ("vote must be ≥ current fork version") and CEN stated the effect ("unconstrained"); both verified at the pin — the predicate exists and cannot fail at the shipped table. A vote signal with nothing to vote for |
| CEN-B3 | The hard-fork **voting machinery** runs on every connect (rolling window 10080, threshold accounting, per-height version persisted) but is inert: one table entry, threshold 0, nothing to advance to. `HardFork::add`'s reject verdict is **discarded** at the DB call site; `add` records the table version (not the block's vote) at each height; the voting window is rebuilt from `split_height` after a reorg; the on-hf-advance pool re-validation arm can never fire post-genesis; `mainnet_hard_fork_version_1_till = 0` and the `HF_VERSION_*` constants (all = 1) feed only dead dispatch | src/cryptonote_basic/hardfork.cpp:134–161; discard src/blockchain_db/blockchain_db.cpp:641; reorg rebuild blockchain.cpp:1494; pool re-validate :6480–6490; constants cryptonote_config.h:280–289 | C | 4 | none | — | RC-142, RC-163, RC-164, RC-165, RC-166, RC-168 ⇒ merged. Rule-60 deletion candidate (RC's position: bucket 3 via rule 60's delete-the-dead-branch command); kept at 4 because deleting the *machinery* — as opposed to individual dead branches — is entangled with the V4-activation question the R4 round must answer by design (rules 75/21). §6 finding |
| CEN-B4 | The block's `attestation_root` must equal the root recomputed from the (possibly empty) credit-wire witness, and every pass record's P-countersignature must verify against the bond's committed hybrid pubkey; nonce binds coinbase `vout[0]` key and the validated `prev_id` (all-zero prev hash refused by the FFI) | 5738 (main) / 2253 (alt) → `verify_block_attestation` 5565–5662; verdict Rust `shekyl_archival_verify_attestation` | C | 1 | spec | [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) §3–§4; RF-D3 | RC-12, RC-13 ⇒ merged. Enforcement status: the mechanism is the full recompute + countersignature verify; pre-population the only valid header value is the empty-set root (`ARCHIVAL_CREDIT_WIRE.md` :214–223), so the ratified-in-full admission recompute is *exercised* only on its empty-root slice until the cutover. The doc's §3 enforcement-status paragraph is stale (names the deleted `check_attestation_root`); spec content stands |
| CEN-B5 | After connect, the header's `curve_tree_root` must equal the root the DB computed by growing the tree with this block's outputs; mismatch pops the block and rejects | 6422–6437 | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) :264, :281; [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) | RC-14 ⇒ merged. Skipped on FAKECHAIN; alt path defers to promotion (CEN-K5) |
| CEN-B6 | Block identity and the PoW hashing blob are `serialize(header) ‖ merkle(miner_tx_hash ‖ tx_hashes) ‖ varint(tx_hashes.size()+1)` — there is no separate merkle-root header field; tampering with `tx_hashes` retargets both identity and PoW | cryptonote_format_utils.cpp:1397–1403 (`get_block_hashing_blob`), 1515–1525 (`get_tx_tree_hash`) | C | 4 | none | — | [m] RC-7 ⇒ minted. CEN scoped identity definitions out (§1.6 of the archived doc); carried here because the PoW check consumes this construction directly. RC decision-log #5: a rewrite that adds an explicit `merkle_root` field is a wire change, not a missing check |
| CEN-B7 | A `major_version` above `get_ideal_version()` logs a one-time warning and does **not** reject (the version-equality reject is CEN-B1; this arm is the old-daemon UX branch) | 5713–5723 | C | 4 | none | — | [m] RC-17 ⇒ minted. Not a reject; recorded because it is an acceptance-path branch a rewrite must consciously keep or drop |

### 4.C Timestamps

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-C1 | Block timestamp must not exceed local wall-clock + `SHEKYL_DAA_FTL_SECONDS` (540) — enforced at **both** block-store admission paths (main connect and alt admission) | rust/shekyl-difficulty/src/timestamp.rs:145 (`check_timestamp_rule`, the ONE implementation; FTL half `is_timestamp_below_ftl` :66) via FFI `shekyl_difficulty_check_timestamp_rule` (difficulty_ffi.rs:365); C++ marshaling shim blockchain.cpp:5612; main 5870 via 5652; alt 2381; cached-template revalidation 1947; genesis-padding cache written at 535 and 938 (init + reset_and_set_genesis_block) (C2-R3-Q3 added this rejection site) | C | 1 | spec | `config/consensus_constants.json` (`daa_ftl_seconds`); [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) §4 :913–914 (values), :1008 ("the values Shekyl ships at genesis"); alt-admission placement: [`CONSENSUS_C2_R3_TIMESTAMPS.md`](../completed/CONSENSUS_C2_R3_TIMESTAMPS.md) §6/§8 (C2-R3-Q3, ratified 2026-09-01); constant-swap record `docs/CHANGELOG.md` :14858–14863 | RC-29 ⇒ merged. The main-path-only gap (a `now+541` block parked in the alt store until promotion) is **closed**: C2-R3-Q3 ruled FTL at alt admission — the promotion-only alternative would have ratified an unbounded clamp-saturation difficulty-decay alt-spam surface. Observed red-first (`gen_block_alt_ts_above_ftl`). FOLLOWUPS row closed |
| CEN-C2 | A candidate block's timestamp must be **strictly greater** than element index 5 (0-based) of the sorted window of the `SHEKYL_DAA_MTP_WINDOW` (11) timestamps immediately preceding it on its own chain — alt path: the **newest 11** of alt suffix + main prefix (the inherited whole-alt-chain median, with epee's even-window averaging, is deleted); windows shorter than 11 are right-padded per CEN-C3; miner templates floor their timestamp at `median + 1` | rust/shekyl-difficulty/src/timestamp.rs:145 (`check_timestamp_rule`; strict `>` has one site, `is_above_mtp` :103; median `mtp_median` :113) via FFI difficulty_ffi.rs:365; C++ shim blockchain.cpp:5612; main 5870 via 5652; alt 2381 after the newest-11 truncation 2376; template floor 1995 (edge-refusal revalidation arm) + cached-template revalidation 1947 | C | 2 | ratified | [`CONSENSUS_C2_R3_TIMESTAMPS.md`](../completed/CONSENSUS_C2_R3_TIMESTAMPS.md) §4/§8 (C2-R3-Q1 + sub-decisions a/b/c, ratified 2026-09-01); shared vectors `docs/test_vectors/MTP_BOUNDARY_V1.json` (consumed by the C++ unit test and the Rust predicate tests); [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) §5.5 refuted-premise correction note | RC-31, CEN §6.3 ⇒ merged. The C1 three-way split (§7.1) resolved on the merits: after the §5.5 "preserved unchanged" premise refutation, C2-R3-Q1 re-derived the boundary from zero and re-ratified **strict** (LWMA-1's pinned sources are boundary-indifferent; commitment 3 arbitrates). Spec aligned and the rule CROSSED to Rust (re-ratified 2026-09-01 after the round's original C++ owner was ruled a rule-20 violation): `shekyl-difficulty::check_timestamp_rule` is the one implementation, consumed by the C++ shim via FFI beside the LWMA-1 entry point. Boundary observed red-first (`gen_block_ts_at_median`; window truncation: `gen_block_alt_ts_window_truncation`) |
| CEN-C3 | Below `SHEKYL_DAA_MTP_WINDOW` blocks of history the median window is right-padded with the genesis timestamp — the same rule runs from block 1; **there is no bootstrap carve-out** (the inherited any-timestamp-under-FTL acceptance below 11 blocks is deleted) | rust/shekyl-difficulty/src/timestamp.rs:155 (padding arm of `check_timestamp_rule` :145); C++ main window build blockchain.cpp:5652–5684 | C | 2 | ratified | [`CONSENSUS_C2_R3_TIMESTAMPS.md`](../completed/CONSENSUS_C2_R3_TIMESTAMPS.md) §5/§8 (C2-R3-Q2, ratified 2026-09-01) | RC-30 ⇒ merged. Replace ruled over keep-with-rationale: composition decided it (one sentence covers every height and both paths, and the padding dissolves the alt near-genesis short/even-window accident); the closed hazard is honestly recorded as small (genesis ts is 0). Observed red-first (`gen_block_ts_below_median_in_bootstrap`). The genesis-mint-timestamp question spun off to FOLLOWUPS, explicitly out of R3 scope |

### 4.D PoW and difficulty

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-D1 | The block's PoW longhash must satisfy the difficulty target (`check_hash(pow, diff)` must pass); FFI failure rejects. The alt path runs it at alt difficulty (CEN-D5); the former CEN-E3 `fast_check` skip is deleted (C2-R1a) | 5818 (main) / 2347 (alt) | C | 1 | spec | PoW-gate design: [`RANDOMX_V2_PLAN.md`](RANDOMX_V2_PLAN.md); difficulty values: [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) | RC-24 ⇒ split across this row and CEN-D1b: the *gate* is Shekyl design; the *comparison form* is D1b |
| CEN-D1b | The acceptance comparison is `hash · difficulty < 2^256` with the 32-byte hash read as a 256-bit little-endian integer — implemented in Rust (`shekyl_difficulty_check_hash`; the inherited 64/128-bit fast/slow split was deleted in the port, proven equivalent over a differential corpus) | src/cryptonote_basic/difficulty.cpp:52–86 (marshaling wrapper + contract comment); rust/shekyl-difficulty (`check_hash`); vectors rust/shekyl-difficulty/tests/check_hash_vectors.rs | C | 4 | KAT-port | vectors + the port record (difficulty.cpp:52–58 comment) | Split from CEN-D1 in C1 (RC-24's bucket-2 reading vs CEN's §5 residue note). The comparison is sealed by vectors, not ratified: whether 2^256-target semantics are right-for-Shekyl was never separately ruled |
| CEN-D2 | The longhash function is RandomX v2 via Rust FFI unconditionally (height/version ignored); on FFI failure the verifier's returned bool is the fail-closed gate — every consumer (main connect, alt path, longhash precompute worker) rejects on it, at **every** difficulty. The `0xff…` hash written on failure is a **belt** for display-only callers that ignore the bool, not the gate: `check_hash(0xff…, 1)` **passes**, so at difficulty 1 the sentinel alone fails open (corrected 2026-09-03; see the note) | cryptonote_tx_utils.cpp:748/:766; src/crypto/pow_registry.cpp:6; fail-closed :784–794; alt pre-seed blockchain.cpp:2325–2326 | C | 1 | spec | [`RANDOMX_V2_PLAN.md`](RANDOMX_V2_PLAN.md) ("C JIT for mining, Rust interpreter for verification — permanent") | RC-22 (hash half), RC-23 ⇒ merged. **P0f correction (round 4, 2026-09-03) — the fail-closed claim as written in this row was overstated, and the code has since been FIXED (PR #604).** `check_hash(0xff…, 1)` passes, and the validation paths *used to* ignore the verifier's returned bool, so with difficulty 1 reachable (`--fixed-difficulty` on any nettype; no organic floor above CEN-D6's zero-guard) the sentinel failed **open** there. The verifier's bool now gates all three consumers, and CSR §5.4.1 CEN-D2 — **CHECKED-CONFORMANT** as of the 2026-09-03 re-review — carries both the original divergence walk (recorded there as history, graded S1) and the post-fix verification |
| CEN-D3 | RandomX seed block: epoch 2048 with lag 64 — `seedheight(h) = 0 for h ≤ 2112, else (h−65) & ~2047`; seed hash is the block id at that height (alt path: resolved along the alt chain when the seed height is on it). The `SEEDHASH_EPOCH_*` env override is refused on public networks (fakechain-only lever, init-time) | rust/shekyl-pow-randomx/src/seed_epoch.rs:109; blockchain.cpp:6493, 2327–2345; env refusal 640–643 | C | 1 | spec | [`RANDOMX_V2_RUST.md`](RANDOMX_V2_RUST.md) :393, :790–823 (seed-epoch schedule spec — note it lives here, not in `RANDOMX_V2_PLAN.md` or `SPEC_ANCHORS.md`); [`RANDOMX_V2_PLAN.md`](RANDOMX_V2_PLAN.md) :171, :201 (non-tunable) | RC-22 (seed half), RC-25, RC-27 ⇒ merged |
| CEN-D4 | Next-block difficulty is LWMA-1 over the last N+1 (=91) blocks (Rust `lwma1_next_difficulty`); below N blocks of history the genesis difficulty constant (100) applies; target block time T = `SHEKYL_DAA_TARGET_SECONDS` (120) | 1082–1175; rust/shekyl-difficulty/src/lwma1.rs | C | 1 | spec | [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) (ratified 2026-05-18); `config/consensus_constants.json` `daa_*` | RC-19, RC-20, RC-21 ⇒ merged. Bias 99/200, clamp 6, min-L 1/20 are deliberate bare literals per the Round-3 disposition |
| CEN-D5 | Alt-chain difficulty: the same LWMA-1 fed by a window stitched from main-chain prefix + alt-chain suffix, window ending at `bei.height−1`; a height-0 alt candidate sentinel-returns difficulty 0 (`CHECK_AND_ASSERT_MES` log-and-return at 1559–1563), which CEN-D6's zero guard then rejects | 1544–1638 | C | 2 | ratified | **RULED C2-R1b (ratified 2026-09-03)** — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b | Q1b: the window SELECTION crosses — `shekyl-difficulty::alt_window_plan` behind `shekyl_difficulty_alt_window_plan` (both regimes, one function; contiguity precondition fails closed to the D6 sentinel); C++ performs the fetches the plan names; vectors `FORK_CHOICE_V1.json`. Prior: RC-26 merged w/ recorded dissent |
| CEN-D6 | A zero next-block difficulty **rejects the block** — `CHECK_AND_ASSERT_MES` is log-and-return-false (`misc_log_ex.h:396`), not a process abort; the value can only be 0 via a difficulty-function sentinel return (e.g. CEN-D5's height-0 arm) | 5766 / 2324 | C | 2 | ratified | **RULED C2-R1b (ratified 2026-09-03)** — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b | Q1b: ratified as the marshaling belt on the FFI result at both call sites — a sentinel-eating shim would convert a difficulty-function failure into a silently accepted block; prior: C1 §7.14 correction |
| CEN-D7 | `--fixed-difficulty` overrides the DAA (regtest lever; height 0 forced to 1) — a test-only carve-out live in the production binary | 1084–1087, 1546–1548 | C | 4 | none | — | RC-28 ⇒ merged. §10 R9 (test-seam design) |

### 4.E Checkpoints and fast-sync trust

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-E1 | In the checkpoint zone, the block id at a checkpointed height must equal the hardcoded/JSON-loaded checkpoint hash | 5829–5837 (main); 2315 (alt; a checkpoint match forces the reorg, 2481) | C | 2 | ratified | **RULED C2-R1b (ratified 2026-09-03)** — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b | Q2 (**existence HELD for C2-R0**; this row's zone-equality semantics ratified *while the mechanism exists*): NO crossing — derivation-free hash equality over epee-fed C++ state; crossing reopens when DRS/R8 moves checkpoint state (trigger re-checked at #595: not live). Prior: RC-16 merged |
| CEN-E2 | An alternative block at or below the last checkpoint preceding the current height is refused (`is_alternative_block_allowed`) | 2233; src/checkpoints/checkpoints.cpp:137 | C | 2 | ratified | **RULED C2-R1b (ratified 2026-09-03)** — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b | Q2 (**existence HELD for C2-R0**; semantics ratified *while the mechanism exists*): the alt-height floor stands as the checkpoint arm's admission fence; prior: RC-135 merged |
| CEN-E3 | **Removed (C2-R1a, ratified 2026-09-02, executed same PR).** Was: compiled-in per-block hash list (`m_blocks_hash_check`, `PER_BLOCK_CHECKPOINT=1` by default) — inside its range a block's id had to equal the compiled hash, and PoW, pool-supplement NIC and per-tx input checks were **skipped** (`fast_check`); pruned-block weights came from the same table | deleted (mechanism, loader, p2p expansion, `--fast-block-sync`, `src/blocks/`, generator) | C | 3 | — | [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §3 (ruling, wargame, reopening criterion — DRP §74.2's "unmade shipping decision" is made: not shipped) | RC-15 ⇒ merged. Every arm was unreachable with the shipped zero-byte data; mainnet's loader pin was stale-impossible; testnet/stagenet loaded unverified — rule 71's defining instance |
| CEN-E4 | **Removed (C2-R1a, ratified 2026-09-02, executed same PR).** Was: `check_tx_inputs` (pool wrapper) returned success unchecked when `kept_by_block` and the chain was below the hash-check size | deleted (same selector as CEN-E3's table; arm unreachable with the shipped empty table) | C | 3 | — | [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §3 | RC-96 ⇒ merged |
| CEN-E5 | Loading a checkpoint JSON file can add checkpoints at runtime (`--enforce-dns-checkpointing`-era mechanism reduced to file load) — operator-supplied consensus pins | src/checkpoints/checkpoints.cpp:195–229; `update_checkpoints` 6699 | C | 2 | ratified | **RULED C2-R1b (ratified 2026-09-03)** — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b | Q2a/Q2b (**existence HELD for C2-R0**; ratified *while the mechanism exists*): wired UNIFORMLY on all public networks (both nettype guards deleted — rule 71); JSON-internal conflict fail-stops with named output; chain-conflict rollback is `saturating_sub(pt.first, 2)` and bounded by Q1c's watermark; the unpopulatable difficulty-points twin and the weekly full-chain recompute are deleted (Q2c) |

### 4.F Miner transaction (structure and emission)

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-F1 | Coinbase has exactly one input, of type `txin_gen` | 1642–1643 | C | 4 | none | — | RC-33, RC-34 ⇒ merged |
| CEN-F2 | Coinbase tx version ≥ 3 | 1644 | C | 2 | ratified | rule 60 (v3-from-genesis); genesis blob is v3 (`033c…`, cryptonote_config.h:368) | RC-35 ⇒ merged |
| CEN-F3 | Coinbase CT type is `CTTypeNull` (no FCMP++ signature material) | 1645 | C | 2 | ratified | rule 60: "`CTTypeNull` for coinbase" | RC-36 ⇒ merged |
| CEN-F4 | Coinbase has exactly 1 output; genesis (caller-derived height 0) exempt; the height operand is caller-derived, not `txin_gen.height` (spoof closed by CEN-F5) | 1647–1675 | C | 1 | spec | [`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md) §12.3 (F-H); FOLLOWUPS "GENESIS-FREEZE: cap the coinbase output count" | RC-37 ⇒ merged |
| CEN-F5 | `txin_gen.height` must equal the block's chain position | 1677–1681 | C | 4 | none | — | RC-38 ⇒ merged |
| CEN-F6 | Coinbase `unlock_time` must equal height + `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60) | 1683; constant cryptonote_config.h (not `config/`) | C | 4 | pinned-not-re-derived | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §13 :907 (frozen domain constraint); [`CT2_DRAIN_ORDER.md`](CT2_DRAIN_ORDER.md) :248 ("60, not 10"); [`MERKLE_TREE.md`](../MERKLE_TREE.md) :201 acknowledges the CryptoNote inheritance | RC-39 ⇒ merged. Demoted from CEN's bucket 2 under the §2 bar: the 60 is frozen and documented, never re-derived. The same 60 drives coinbase tree maturity (CEN-L12). §10 R5 |
| CEN-F7 | Coinbase output amounts must not overflow when summed | 1686 (`check_outs_overflow` cryptonote_format_utils.cpp:899) | C | 4 | none | — | RC-40 ⇒ merged |
| CEN-F8 | Coinbase outputs must be `txout_to_tagged_key` (view-tagged; sole output type) — same commitment as CEN-H12, enforced separately at the miner-tx surface (the coinbase never passes the H path) | 1692 (`check_output_types` cryptonote_format_utils.cpp:971) | C | 2 | ratified | as CEN-H12 | RC-41 ⇒ merged |
| CEN-F9 | Coinbase output keys must be canonical, prime-order, non-identity points (Rust batch check) | 1697 (`check_outs_valid` cryptonote_format_utils.cpp:837) | C | 1 | spec | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3 | RC-42 ⇒ merged. Miner tx never passes `check_tx_semantic`; this is the only site |
| CEN-F10 | Coinbase commitment masks: canonical prime-order, non-trivial (≠ identity, ≠ G), and ≠ `zeroCommit(amount)` (the amount-leaking fingerprint) | 1699 → 3287–3341; Rust `shekyl_check_commitment_masks` | C | 1 | spec | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3 | RC-43 ⇒ merged. Sole mask gate for `CTTypeNull` |
| CEN-F11 | Genesis (height 0) emission is accepted as configured (`GENESIS_TX` blob per nettype); structure validated, amount not recomputed | 1754–1761; init 508–517 | C | 1 | spec | genesis pipeline ([`GENESIS_TRANSPARENCY.md`](../GENESIS_TRANSPARENCY.md), [`GENESIS_ALLOCATIONS.md`](../GENESIS_ALLOCATIONS.md)) | RC-44 ⇒ merged |
| CEN-F12 | Decomposed-denomination check on coinbase outputs is **dead code**: the gate is `if (version == 3)` where `version` is the *hard-fork* version parameter — the sole caller passes `m_hardfork->get_current_version()` (:6272), which is always 1, so `is_valid_decomposed_amount` (and its CryptoNote denomination table) never runs | 1763–1770 (gate); lookup `is_valid_decomposed_amount` cryptonote_format_utils.cpp:1528–1532; table literal `valid_decomposed_outputs[]` :53 | C | 4 | none | — | RC-45, RC-46, CEN §6.8/§6.10 ⇒ merged; adjudicated by C1 steering: **CEN-F12's demotion stands**, and #583 corrected RC-45's first-draft "always-on" reading in-PR ("keys off HF version"). Load-bearing dead: with the 1-output cap (CEN-F4) and exact payout (CEN-F18) the single output is `emission+fees`, essentially never a table denomination — a Rust port implementing this arm as live would reject nearly every block. Examined-and-mooted trail: `GENESIS_TX_WIRE_FORMAT.md` :454 (Q2) sheds the *chunking*, not this gate; `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` :973 + §12.3 F-H recommends the 1-output cap ("Recommended", no ratified marker). Rule-60 deletion candidate (dead HF branch) |
| CEN-F13 | Base subsidy: `(MONEY_SUPPLY − already_generated) >> 21`, floored at tail subsidy 600 000 000 atomic/block; computed in Rust (`shekyl-economics::block_reward_with_penalty`), C++ is a marshaling shim | 1776 → cryptonote_basic_impl.cpp:93/:148 → rust/shekyl-economics/src/emission.rs:142 | C | 1 | spec | `config/economics_params.json`; [`ECONOMY_EXPLAINED.md`](../ECONOMY_EXPLAINED.md); 81-vector cross-language KAT | RC-48 ⇒ merged (curve legs split out as RC-169–172 map to F14/F15/F20) |
| CEN-F14 | Weight bound at the reward function: weight > 2·effective-median rejects (`BLOCK_TOO_BIG`); **exactly** 2·median is accepted at zero subsidy — the inclusive bound is a deliberate, recorded divergence from the inherited exclusive bound | emission.rs:150–176; reject surfaces 1776–1780; divergence recorded cryptonote_basic_impl.cpp:122–135 | C | 1 | spec | Stage-1 PR 7; the recorded divergence comment; 81-vector KAT | RC-169 ⇒ merged. The penalty *curve* between median and 2·median is CEN-F14b |
| CEN-F14b | The subsidy penalty curve: median soft-raised to the 300 000-byte free zone; weight ≤ median ⇒ full subsidy; median < weight ≤ 2·median ⇒ quadratic penalty `base·(2m−w)·w/m²` in u128 (fail-closed on overflow) — the inherited ArticMine/CryptoNote curve shape, ported to Rust under KAT | emission.rs:150–176 | C | 4 | KAT-port | `docs/CHANGELOG.md` :1178 (81-vector KAT asserted from both languages) | Split from CEN-F14 in C1. Survey A claimed the penalty was "examined in the A3 fee round" — **no locatable A3-round record exists** (searched docs/completed/, docs/design/, decision log); the locatable trail is the KAT plus the submit-path fee exam (CEN-M3), so the class is KAT-port, not ratified. §10 R2. **R2 DEFERRED** (Rick 2026-09-03, §10) pending FL-R12′ |
| CEN-F15 | Release-rate multiplier: subsidy scaled by `clamp(tx_volume_avg·10⁶/baseline, 0.8·10⁶, 1.3·10⁶)/10⁶`, then capped to remaining supply (saturating; defends uint64 underflow past the cap) | cryptonote_basic_impl.cpp:148–168; rust/shekyl-economics/src/release.rs:24 | C | 1 | spec | `config/economics_params.json` (`shekyl_release_min/max`, `shekyl_tx_volume_baseline` 50); [`ECONOMY_EXPLAINED.md`](../ECONOMY_EXPLAINED.md) | RC-170, RC-171 ⇒ merged |
| CEN-F16 | Emission split: subsidy divides into miner and staker legs (`compute_emission_split`, Rust); the coinbase may pay only the miner leg | 1783–1785 | C | 1 | spec | [`ARCHIVAL_BUDGET_SCHEDULE.md`](ARCHIVAL_BUDGET_SCHEDULE.md) §2.2 (F-B1c operand discipline) | RC-49 ⇒ merged |
| CEN-F17 | Fee burn split: fees divide into `miner_fee_income` / staker pool / destroyed (`compute_fee_burn`, Rust; operands: fee sum, tx-volume avg, circulating supply, frozen segment count); the coinbase may pay only `miner_fee_income` | 1791–1792 | C | 1 | spec | `config/economics_params.json` `SHEKYL_BURN_*`; [`ECONOMY_EXPLAINED.md`](../ECONOMY_EXPLAINED.md); [`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md) §12.11.1 | RC-50 ⇒ merged |
| CEN-F18 | The coinbase must pay **exactly** `miner_emission + miner_fee_income` — both overpay and underpay reject | 1794–1803 | C | 1 | spec | economics set above; exact-equality (vs ≤) is part of the split design | RC-47 ⇒ merged |
| CEN-F19 | `frozen_segment_count` (the D2 escalation operand) must be read at parent state: `m_db->height()` must equal the block's height at the read point or the node halts; verify's operand IS the accrual's operand (single-read discipline) | 1732–1743, 6271 | C | 1 | spec | [`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md) §12.12 :2121 (the read-point ruling — the "single asserting reader"; note it is §12.12, not §6.2) | RC-52 ⇒ merged |
| CEN-F20 | `tx_volume_avg` is the integer mean of `tx_hashes.size()` over the prior `SHEKYL_TX_VOLUME_WINDOW` (720) blocks; height 0 → 0 | 2111–2129 (`get_tx_volume_avg`); rust/shekyl-economics/src/activity.rs | C | 1 | spec | `shekyl-economics` activity spec; window 720 is a consensus-visible constant **not** in `config/` (RC decision-log #10 class) | [m] RC-172 ⇒ minted |
| CEN-F21 | `genesis_ng_height` at connect is **1**: `get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG)` returns the table row's height 1, not 0; genesis (height 0) is `original_version` 1 but not that lookup — the emission-split operand is therefore 1 | src/cryptonote_basic/hardfork.cpp:383–394; used blockchain.cpp:1783, 6345 | C | 1 | spec | v3-from-genesis table; economics.h deleted-gate comment (RC-182's evidence) | [m] RC-182 ⇒ minted. Independently ratifiable from "NG from genesis" |

### 4.G Block body (per-tx and block-level, main-chain connect)

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-G1 | No listed tx may already exist in the chain | 5936–5941 (belt: `TX_EXISTS`, CEN-L3) | C | 4 | none | — | RC-18 ⇒ merged. The **miner tx** is not in `tx_hashes` and is not covered here — its only uniqueness gate is the DB write (CEN-L3 note). Duplicate hashes *inside* `tx_hashes` are not uniquely rejected here either; the second insert hits `TX_EXISTS` |
| CEN-G2 | Every listed tx hash must resolve from the mempool or the block's pool supplement; otherwise reject with `m_missing_txs` (taken pool txs are returned on any failure) | 5969–6007 | C | 4 | none | — | tx content ↔ hash agreement is established here by lookup-under-computed-hash; the DB layer trusts it (§6, CEN-L4) |
| CEN-G3 | Pool-supplement txs must pass the full non-input consensus set at the current HF version before the block may connect | 5860 (main) / 2380 (alt) | C | 4 | none | — | the NIC set itself is CEN-H* |
| CEN-G4 | Every listed tx must pass `check_tx_inputs` at connect; failure marks the block invalid and rejects it. FCMP++ txs that verified at pool admission skip only the FCMP proof re-verify (structural checks re-run) | 6036–6064 | C | 1 | spec | skip placement: [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §71–§72.1 (`hop` is pool-admission-side verification; moving it re-derives the embargo) | cache: CEN-M8 |
| CEN-G5 | When syncing pruned blocks, the block weight must be available from the compiled hash-check table | 6073–6081 | C | 4 | none | — | |
| CEN-G6 | Weight-limit frozen bounds: long-term window 100 000 blocks, short-term surge ×50 | 6580, 6593; constants cryptonote_config.h | C | 4 | pinned-not-re-derived | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §10 :803 (block-level bounds table — a freeze, not a derivation) | Demoted from CEN's bucket 2 under the §2 bar: the freeze record exists; no examination of the ×50 or the window value does. §10 R2. **R2 DEFERRED** (Rick 2026-09-03, §10) pending FL-R12′ |
| CEN-G6b | Weight-limit remainder: effective median = clamp(short-term median, long-term effective median, 50×long-term), floored at the 300 000-byte penalty-free zone (`…FULL_REWARD_ZONE_V5`); **limit = 2 × median**; long-term weight = weight clamped to [median·10/17, median·1.7]. `get_min_block_weight(version)` ignores its version argument and always returns the V5 zone | 6440, 6568–6607, 6548–6566, 1809–1870; vestigial version arg cryptonote_basic_impl.cpp:81–85 | C | 4 | none | — | RC-133, RC-181 ⇒ merged. The V5 reward-zone value's arbitration was explicitly punted "to the economics doc" (`GENESIS_TX_WIRE_FORMAT.md` :806–811, the "fossil flag") and never landed anywhere — no economics doc, decision-log entry, or (pre-#584) FOLLOWUPS row received it; 300 000 is consumed as given at [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md) :130 and decision log :4686. The 1.7× clamps ride along unexamined. FOLLOWUPS row (owner: this doc). §10 R2. The reward-side 2·median rejection is CEN-F14. **R2 DEFERRED** (Rick 2026-09-03, §10) pending FL-R12′ |
| CEN-G7 | No two serve-credit vins in one block may carry the same (P, shard, E) — checked across txs against the `ArchivalPairEpochKey` byte encoding | 6102–6131 | C | 1 | spec | [`ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md`](../completed/ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md) D-SC-C; PC-D4 non-widening rationale at the site | RC-113 ⇒ merged. Mirrored in Rust `serve_credit_block_unique` |
| CEN-G8 | **Retired (C2-R1a, ratified 2026-09-02 — the first retired bucket-1 row).** Was: under the compiled-hash fast path, a debit-side bond post (bond_debit > 0) had to authorize against the record's committed `bond_spend_pk` (the GF-1 theft-shaped belt). Jobs enumerated and covered: the belt existed only because CEN-E3 skipped per-tx verify; with the fast path deleted, `check_archival_bond_post_input` (the primary pin, CEN-J13) is unconditional at block connect | deleted with its selector (`fast_check`); `check_debit_auth_single_source.sh` updated to three required sites | C | 3 | — | [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §3.1; GF-1: [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §9.6; [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.5 step 5 | belt's one job subsumed by the now-unconditional primary |
| CEN-G9 | No two emission claims in one block may name the same (P, E) pair (Rust `shekyl_emission_block_claims_unique` over 40-byte P‖epoch_le entries) | 6210–6252 | C | 1 | spec | [`REWARD_EMISSION_E3_GATING_ROUND.md`](../completed/REWARD_EMISSION_E3_GATING_ROUND.md) §6.2 layer 2 | RC-130 ⇒ merged. Serve-credit + Unbond same-P same-block deliberately NOT rejected (ratified 2026-07-12, site comment 6147–6152) |
| CEN-G10 | At most one bond post per P per block (Rust `shekyl_archival_bond_post_block_unique`) | 6253–6261 | C | 1 | spec | [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.5 | RC-123 ⇒ merged |
| CEN-G11 | Per non-genesis block, staker inflow (staker emission leg + staker fee-pool share) is accrued to `archival_budget_accrual`, and the destroyed fee share is burn-recorded; operands are exactly `validate_miner_transaction`'s — `compute_emission_split(base_reward, height, genesis_ng_height)` :6347 and `compute_fee_burn(fee_summary, tx_volume_avg, already_generated_coins, frozen_segment_count)` :6350; **neither takes a version** | 6282–6356, 6447–6460; tripwire `scripts/ci/check_archival_reward_gates.sh` | C | 1 | spec | [`ARCHIVAL_BUDGET_SCHEDULE.md`](ARCHIVAL_BUDGET_SCHEDULE.md) §2.2 (F-B1a/c; tripwire records F-B1b as RETIRED) | RC-131, RC-132 ⇒ merged. Consensus state write, not a check. The comment at :6293–6306 still narrates the retired `bl.major_version` operand — stale, contradicted by the calls below it (§7) |
| CEN-G12 | `already_generated_coins` advances by the full subsidy, clamped at `MONEY_SUPPLY` (single Rust entry point `shekyl_advance_already_generated`; the former two hand-written C++ copies were deleted as a drift pair) | 6374; alt bookkeeping 2303 | C | 1 | spec | site comment 6364–6373; `consensus_constants.json` division-one-site note | RC-51 ⇒ merged. Alt bookkeeping advances by coinbase-paid, not subsidy — CEN-K8 |
| CEN-G13 | Genesis (height 0) has no staker accrual: its emission is the configured blob, paid whole by the coinbase | 6337–6343 | C | 1 | spec | site comment; genesis docs (CEN-F11) | |

### 4.H Transaction: non-input consensus, semantics, outputs

All rows here are enforced at **both** pool admission (`ver_non_input_consensus` from `tx_pool.cpp:236`) and block connect (pool-supplement verify, CEN-G3) — one rule, two sites — except where noted.

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-H1 | Serialized tx size ≤ `CRYPTONOTE_MAX_TX_SIZE` (1 000 000 bytes) | tx_verification_utils.cpp:66; cryptonote_core.cpp:728; cryptonote_basic_impl.cpp:88–90 | C | 4 | pinned-not-re-derived | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §10 :790 (frozen limit) | RC-53 ⇒ merged. Demoted from CEN's bucket 2 under the §2 bar: frozen, never derived. Constant hand-maintained (cryptonote_config.h:42), not `config/`. **R2 DEFERRED** (Rick 2026-09-03, §10) pending FL-R12′ |
| CEN-H2 | Tx version must be exactly 3 (the HF-dispatched min/max table collapses to 3..3 at HF1; independently re-enforced at CEN-I3) | tx_verification_utils.cpp:55–78 | C | 2 | ratified | rule 60 v3-from-genesis; [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) :491, Q12 ruling :654–655 (deliberate keep; V4 = future lattice-only) | RC-68 ⇒ merged. The dead 1..1/2..2 dispatch arms are rule-60 deletion residue; the drift-pair with CEN-I3's hardcoded 3..3 is a live FOLLOWUPS row (repointed here) |
| CEN-H3 | Tx weight ≤ half the minimum block weight minus coinbase reserve (= 149 400) | tx_verification_utils.cpp:82, 203–210 | C | 4 | examined-disposition | [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) §8 row N3 :1271 — examined on the **submit path** only | RC-69 ⇒ merged. Demoted from CEN's bucket 2 under the §2 bar; the block-connect side of the same limit was never separately examined, and the limit formula is inherited scaling. §10 R2. **R2 DEFERRED** (Rick 2026-09-03, §10) pending FL-R12′ |
| CEN-H4 | Non-coinbase tx must have ≥ 1 input | cryptonote_core.cpp:774–779 | C | 4 | none | — | RC-57 ⇒ merged |
| CEN-H5 | Input-variant whitelist: `txin_gen` forbidden outside coinbase; only `txin_to_key` and the three archival variants (`serve_credit_response`, `bond_post`, `reward_emission`) are accepted; `txin_to_script`/`txin_to_scripthash` rejected everywhere (incl. the double-spend visitor and the DB whitelist) | cryptonote_format_utils.cpp:773–834; blockchain.cpp:3162–3168; blockchain_db.cpp:398–402 | C | 1 | spec | archival vin taxonomy: [`REWARD_EMISSION_E3_GATING_ROUND.md`](../completed/REWARD_EMISSION_E3_GATING_ROUND.md) Q3/Q11; rule 60 "Accepted transaction types" | RC-58, RC-59 ⇒ merged. **Promoted from CEN's bucket 4**: the whitelist is the E3-ruled vin taxonomy (RC's reading, evidence located). The script-variant *type fossils* remain rule-60 deletion residue — §10 R5, and the double-spend visitor joins them. **P0f correction (2026-09-03):** the visitor cited here is **dead** (only call commented out at `blockchain.cpp:6106` — as this census's own §5 item 3 and CEN-L1's row already record) and its body accepts `txin_gen`; live enforcement is site 1 (relay admission + pool-supplement connect via `ver_non_input_consensus`), `check_tx_inputs`' typed dispatch at connect, and the DB backstop for script variants — CSR §5.4.1 CEN-H5 carries the corrected walk |
| CEN-H6 | Archival vin mixing: serve-credit vins mix with nothing; ≤ 1 bond post; ≤ 1 emission; emission and bond-post never co-reside; key-imaged `txin_to_key` are the only permitted co-residents of a bond post or emission (single-sourced in `classify_archival_tx`) | cryptonote_format_utils.cpp:802–833; cryptonote_basic.h:353 | C | 1 | spec | E3 §2.1 (Q3 arity), §2.2 (Q11 mixing), §9.5 item 4 | RC-60, RC-61 ⇒ merged |
| CEN-H7 | Every output must yield a canonical, prime-order, non-identity output key (Rust batch `shekyl_check_output_keys`) | cryptonote_format_utils.cpp:837–866; via cryptonote_core.cpp:790 | C | 1 | spec | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3; output-point validity ratified 2026-07-22 (:404–408) | RC-62 ⇒ merged. Stricter than the inherited `check_key` |
| CEN-H8 | For v>1: `outPk` count == vout count (re-checked locally by the mask gate, and at parse/expand) | cryptonote_core.cpp:797–805; blockchain.cpp:3298; cryptonote_format_utils.cpp:137–140 | C | 4 | none | — | RC-55, RC-63 ⇒ merged |
| CEN-H9 | Output amounts must not overflow on summation; input-side sum covers only `txin_to_key.amount` — archival vins exempt (their value is CT-side/opaque) | cryptonote_core.cpp:808–814; cryptonote_format_utils.cpp:869–920 | C | 4 | none | — | RC-64 ⇒ merged. Amounts on `txin_to_key` are 0 under CT; a leftover overflow belt |
| CEN-H10 | No key image may repeat within one tx (archival vins skipped — no key image) | cryptonote_core.cpp:819 (`check_tx_inputs_keyimages_diff` :913–942) | C | 4 | none | — | RC-65 ⇒ merged with a recorded judgment disagreement: RC read this bucket 1 (FCMP nullifier uniqueness); the *requirement* is independently guaranteed by the ratified CEN-I5 (strictly-descending order forbids duplicates), and this site is the inherited belt — the I-family round that rules I5 sweeps it |
| CEN-H11 | Key images must be in the prime-order subgroup and not the identity (`ki ≠ identity`, `order·ki == identity`) | cryptonote_core.cpp:835 (`check_tx_inputs_keyimages_domain` :963–980) | C | 4 | examined-disposition | [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) §8 row M8 :1289 (thin-port ⚠, pinned vectors) — submit-path exam, not a ratification. The *output-point* torsion posture is ratified ([`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) :363 CT points, :404–408 output points; [`CT2_DRAIN_ORDER.md`](CT2_DRAIN_ORDER.md) :184) but those rulings cover outputs, not the KI domain check | RC-67 ⇒ merged. Demoted from CEN's bucket 2 under the §2 bar. §10 R6; couples to the open FCMP y-normalization question (§3.4) |
| CEN-H12 | Every output must be `txout_to_tagged_key` (view tag required; sole output type from genesis) | cryptonote_format_utils.cpp:971–996; sites cryptonote_core.cpp:843, blockchain.cpp:3393, 1692 | C | 2 | ratified | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.2 :308–309 ("`view_tag` becomes mandatory"; "The **sole** genesis output type"); [`FA-6_VIEW_TAG_ML_KEM.md`](FA-6_VIEW_TAG_ML_KEM.md) (S1–S9 closed: S1–S4/S6–S9 signed 2026-06-02, S5 ratified same date); DSV matrix M9/O5 | RC-78 ⇒ merged. Dead `hf > / < VIEW_TAGS` grace arms (cryptonote_format_utils.cpp:985–1001) are rule-60 deletion residue (RC-167 ⇒ merged here). The ML-KEM tag *derivation* is FA-6's wallet-side surface |
| CEN-H13 | Non-coinbase tx version < 3 rejected at output check (dup of CEN-H2, third site) | blockchain.cpp:3348–3353 | C | 2 | ratified | as CEN-H2 | RC-73 ⇒ merged |
| CEN-H14 | All vout amounts must be 0 (confidential) — except a well-formed archival **emission** tx, whose non-zero ("loud") vouts are the reward commit set | blockchain.cpp:3355–3374 | C | 1 | spec | zero-amount base: [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §9.6 :769; loud-emission exemption: [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §5.5 :494–503 ("emission mint is not confidential") — NOT `REWARD_EMISSION_VIN_PLAN.md` §4 (PR sequencing; the in-code pointer is broken, §7) | RC-74 ⇒ merged. Uses `classify_archival_tx`, not a bare vin count |
| CEN-H15 | CT type must be `CTTypeNull` or `CTTypeFcmpPlusPlusPqc`; anything else rejected (again in the batch verifier; `CTTypeNull` re-rejected for non-coinbase at input check) | blockchain.cpp:3376–3382; tx_verification_utils.cpp:221–239; blockchain.cpp:3626 | C | 2 | ratified | rule 60 ("Accepted transaction types … Anything else is a consensus error") | RC-75, RC-70 (type half) ⇒ merged |
| CEN-H16 | `unlock_time` must be < `CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL` (500 000 000): timestamp-based unlocks are consensus-rejected; height form otherwise unconstrained for non-coinbase | blockchain.cpp:3384–3389 | C | 2 | ratified | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) :888–891 (ratified creation cut); Decision 13 (`docs/CHANGELOG.md` :26409–26411); decision-log :4325–4327 (height-not-manipulable-time rationale) | RC-77 ⇒ merged. The unlock_time triple-divergence (consensus-legal / relay-illegal CEN-M5 / tree-inert CEN-L12) is a §6 finding |
| CEN-H17 | Output commitment masks (all txs): canonical prime-order, non-trivial; coinbase additionally ≠ `zeroCommit(amount)` | blockchain.cpp:3287–3341 (sites 3401, 1699) | C | 1 | spec | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3; Rust `shekyl-ct-balance` | RC-79 ⇒ merged |
| CEN-H18 | CT cleartext balance: `sum(pseudoOuts) = sum(outPk masks) + fee·H`, canonical points, verified in Rust (`shekyl_verify_ct_balance`), single-sourced with the builder | src/fcmp/ct_semantics.cpp:206–231 | C | 1 | spec | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3; site comment | RC-70 (balance half) ⇒ merged |
| CEN-H19 | Bulletproof+ layout must be canonical (`nbp == 1`, length exact by `nout`, `L.size() ≥ 6`, max amounts ≥ vout count, V reconstructed as `mask·INV_EIGHT`) and the aggregate range proof must verify (batched across the block's txs) | ct_semantics.cpp:233–240; ct_types.cpp:240; src/fcmp/bulletproofs_plus.cc; expand-time structural half cryptonote_format_utils.cpp:170–192 | C | 4 | none | layout bound frozen: [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §10 (canonical-form corollary rows) | RC-56, RC-97, RC-70 (BP+ half) ⇒ merged. The verifier is the largest inherited-crypto implementation still on the acceptance path; [`CPP_INHERITANCE_INVENTORY.md`](../CPP_INHERITANCE_INVENTORY.md) :190 carries only a **tentative categorization pending re-verification** — no disposition. Serve-credit exempt (RF-D9). §10 R6 |
| CEN-H20 | Serve-credit-only tx CT shape: no `pqc_auths`, no vouts, zero fee, no outPk/BP+/proof/pseudoOuts, type `CTTypeFcmpPlusPlusPqc`, and the fee-only balance `sum(masks) + fee·H = identity` holds vacuously | tx_verification_utils.cpp:113–131; ct_semantics.cpp:372–401; re-checked blockchain.cpp:3656–3688 | C | 1 | spec | gate-2 §5 ([`ARCHIVAL_RETENTION_GATE2.md`](../completed/ARCHIVAL_RETENTION_GATE2.md)); [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md) | RC-109 ⇒ merged |
| CEN-H21 | Bond-post tx CT shape: `pqc_auths` == vin count, ≥ 1 spend (funding) input, pseudoOuts == spend count, non-empty FCMP++ proof, CT balance with (credit, debit) = (`bond_credit`, `bond_debit`); funding inputs: empty offsets, unspent KIs, FCMP++ over the spend subset (same ref-age/depth as CEN-I10–I15) | tx_verification_utils.cpp:132–148; ct_semantics.cpp:315–336; funding blockchain.cpp:3548–3564, 3765–3874 | C | 1 | spec | [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | RC-119, RC-120 ⇒ merged. The funding-floor C++ copy is disclosed as pending a Rust single-source (:3772–3779) |
| CEN-H22 | Emission tx CT shape: reward total = checked sum of vout amounts, must be > 0; proof presence ⇔ fee inputs present; pseudoOuts == fee-input count; balance `sum(pseudoOuts) + total_reward·H = sum(masks) + fee·H` (mint rides the debit slot) | tx_verification_utils.cpp:149–181; ct_semantics.cpp:338–370 | C | 1 | spec | E3 §2.2 (`verCtSemanticsEmission` KATs); [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) :1445 row EV4 | RC-127 ⇒ merged. Rust checked-sum shared with CEN-J24 |
| CEN-H23 | A tx must deserialize via `binary_archive` and `expand_transaction_1` must succeed; failure rejects | cryptonote_format_utils.cpp:199–208 (`parse_and_validate_tx_from_blob`), 130–196 (expand) | C | 4 | none | — | [m] RC-54 ⇒ minted. Wire-format boundary twin of CEN-A6; the format itself is [`BLOCK_TX_WIRE_FORMAT_PORT.md`](BLOCK_TX_WIRE_FORMAT_PORT.md)'s subject |
| CEN-H24 | Ring-members residue check: for each `txin_to_key`, no relative `key_offset` after the first may be 0 ("duplicate ring members"); archival vins skipped; the unused `hf_version` parameter is ring-era residue | cryptonote_core.cpp:945–961 (`check_tx_inputs_ring_members_diff`); semantic caller :822 area | C | 3 | — | rule 60 **names mixin enforcement** in its deleted-from-construction list; FCMP++ requires empty `key_offsets` (CEN-I6), so this can only fire before CEN-I6 rejects the same tx | [m] RC-66 ⇒ minted at RC's bucket: a live-but-redundant mixin-era check with a named deletion disposition. §10 R5 executes |

### 4.I Transaction inputs — the FCMP++ spend path

Enforced at pool admission (`tx_pool.cpp:304` → `Blockchain::check_tx_inputs`) and at block connect (CEN-G4) — two sites per row unless noted.

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-I1 | Non-serve-credit v≥2 txs must have ≥ 2 outputs | 3466–3474 | C | 2 | ratified | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) :167 (oracle pass 2026-06-21: "earlier 'exactly one' was over-strict"), §2.5 :469; [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) §8 row K1 :1321 | RC-72 ⇒ merged (RC labelled its keep-rationale "oracle fidelity — weak 2"; the located oracle-pass record clears the §2 bar) |
| CEN-I2 | Non-coinbase txs must be `CTTypeFcmpPlusPlusPqc` (ring-based inputs unrepresentable; non-FCMP/non-archival classified txs reject); the FAKECHAIN carve-out at 3476 exempts this row **and** CEN-I3/I4 | 3476–3483, 3615–3620 | C | 2 | ratified | rule 60; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | RC-76, RC-86 ⇒ merged |
| CEN-I3 | Tx version exactly 3 (min == max == 3, hardcoded independently of the HF dispatch); FAKECHAIN exempt | 3493–3506 | C | 2 | ratified | as CEN-H2 (Q12) | RC-82 ⇒ merged. Drift pair with CEN-H2's table form — FOLLOWUPS row repointed here |
| CEN-I4 | ≤ `FCMP_MAX_INPUTS_PER_TX` (8) inputs — the cap covers total `vin.size()`, not just the key-image subset; FAKECHAIN exempt | 3485–3491; cryptonote_config.h:311 | C | 1 | spec | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §10 :788 (frozen), :165 (cap widened in the oracle pass); [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) :1155; embargo coupling [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) | RC-81 ⇒ merged. Hand-maintained constant, not `config/` |
| CEN-I5 | `txin_to_key` key images must be strictly **descending** by `memcmp` — one rule, two guarantees: rejects unsorted AND in-tx-duplicate key images; no-key-image archival vins exempt | 3509–3530 | C | 2 | ratified | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §12 :871 (strictly descending); the examination found and fixed a reversed-direction consensus bug against the oracle (:162–163); DSV matrix K2 :1322 | RC-83 ⇒ merged. Overlaps CEN-H10 for the duplicate half |
| CEN-I6 | `key_offsets` must be empty on every `txin_to_key` (no ring offsets exist under FCMP++) | 3599–3605 (also 3552, 3576 on archival co-resident spends) | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §7 step 3a; rule 60 (decoy path deleted) | RC-84 ⇒ merged |
| CEN-I7 | No input's key image may already be spent on-chain (per-input DB lookup); the storage layer independently re-enforces at connect (CEN-L1) | 3607–3612 (also 3558, 3582) | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §7 step 0 | RC-85 ⇒ merged. Inverse spot-check row. Pool twin is CEN-M6 |
| CEN-I8 | `pqc_auths` count == vin count (serve-credit excepted: must be zero) | 3636–3643, 3656–3664 | C | 1 | spec | [`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md); [`FCMP_SPEND_SIGNING_PREIMAGE.md`](FCMP_SPEND_SIGNING_PREIMAGE.md); gate-2 (vin-borne serve-credit signature) | RC-87, RC-100 (count half) ⇒ merged |
| CEN-I9 | `pseudoOuts` count == input count (regular spend; archival shapes use their spend-subset counts, CEN-H21/H22) | 3645–3654 | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | RC-88 ⇒ merged |
| CEN-I10 | `referenceBlock` must be an existing main-chain block | 4191–4198 | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §7 step 1a | RC-89 ⇒ merged |
| CEN-I11 | `referenceBlock` age window: ≥ `FCMP_REFERENCE_BLOCK_MIN_AGE` (5) and ≤ `FCMP_REFERENCE_BLOCK_MAX_AGE` (100) blocks old | 4200–4220 | C | 1 | spec | `config/consensus_constants.json`; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §7 step 1 (MIN_AGE=5 reorg-margin rationale); value pin = Decision 14 (`docs/CHANGELOG.md` :26404–26407; `docs/audit_trail/2026-05-ffi-constant-drift-audit.md` :69) | RC-90, RC-91 ⇒ merged. **No docs/design pin for the values** — the CHANGELOG Decision-14 entry is the ruling record (enforcement-status caveat carried from §8) |
| CEN-I12 | The membership anchor is the curve-tree root **as it stands after `referenceBlock` connects** — a state property with two consensus-bound witnesses: the header's `curve_tree_root` (the block's attestation, checked against the computed root at connect, CEN-B5) and the node's own per-height root record (written at that connect). The verifier reads its own computed record, never the header — all three `check_tx_inputs` arms do (`:3810`, `:3959`, `:4217` at `d9d27c752`) | 4224–4226 | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §7 step 2 — **reconciled 2026-09-04**: split from its first commit — the pseudocode named the record, the prose narrated the header read the code performed until `292c00aff7` (2026-04-13) | Ruled 2026-09-04 (§7 #16): state, not claim. The in-code FAKECHAIN comment states a consequence, not the rationale — the two witnesses differ only where CEN-B5 is skipped (R9), so the choice is observable only in tests. CSR register re-review owed at the merged sha |
| CEN-I13 | `curve_trees_tree_depth` ∈ [1, current tree depth]; layers passed to verify are depth+1 | 4236–4244, 4291–4292 | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §7 step 2c; [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) | RC-92 ⇒ merged. **Found, not ruled (§7 #16):** step 2b/2c's pseudocode says equality with the depth *at `referenceBlock`*; the code range-checks against the *current* depth, and the FFI binds the claimed depth to the proof (`proof.rs`: `proof.tree_depth != tree_depth` rejects; the root is deserialized at that layer count). Same internally-split shape as CEN-I12; the spec column still needs its own reconciliation |
| CEN-I14 | The FCMP++ proof must be non-empty | 4246–4252 | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | RC-93 ⇒ merged |
| CEN-I15 | FCMP++ membership+spend-auth proof verifies in Rust (`shekyl_fcmp_verify`) over: proof bytes, all key images, all pseudoOuts, per-input PQC leaf hashes (`shekyl_fcmp_pqc_leaf_hash` of each hybrid pubkey — the in-circuit 4th leaf scalar; per-input hash failure rejects), tree root, layers = depth+1, and the tx prefix hash | 4254–4314 (leaf hashes 4265–4274) | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §7 step 4; [`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md); PQC leaf KATs | RC-94, RC-95 ⇒ merged. **Inverse spot-check row.** Skippable on block connect only via the pool cache (CEN-M8) — load-bearing for D++ `hop` |
| CEN-I16 | Per-input hybrid PQC auth structure: `auth_version == 1`; `flags == 0`; `scheme_id` ∈ {1 solo, 2 multisig} (cross-input scheme agreement NOT required — MSW-6 withdrawn); solo key blob exactly `PQC_HYBRID_SINGLE_KEY_LEN` (1996); multisig blob ∈ [3, `PQC_MAX_PUBLIC_KEY_BLOB` 16384] with the exact parse Rust-side | tx_pqc_verify.cpp:161–221; MSW-6 comment blockchain.cpp:4325–4347 | C | 1 | spec | [`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md); [`PQC_MULTISIG.md`](../PQC_MULTISIG.md) §16.3 (MSW-6), MSW-1 | RC-101, RC-102, RC-103, RC-104 ⇒ merged. Inverse spot-check row |
| CEN-I17 | The PQC-signed payload binds, per input: full tx prefix ‖ CtSig base ‖ keccak256(prunable) ‖ that input's PQC header ‖ keccak256 of **every** input's hybrid pubkey — neither the FCMP++ proof nor any input's key can be swapped without invalidating signatures. Cross-input key hashes use Keccak, **not** `shekyl_fcmp_pqc_leaf_hash` (Blake2b-512 domain `shekyl-pqc-leaf`) | tx_pqc_verify.cpp:62–158 (prunable bind :92–95; cross-input bind :133–143) | C | 1 | spec | [`FCMP_SPEND_SIGNING_PREIMAGE.md`](FCMP_SPEND_SIGNING_PREIMAGE.md) :27–36 (exact formula) | RC-105, RC-107 ⇒ merged |
| CEN-I18 | The hybrid signature (Ed25519 **and** ML-DSA, or M-of-N multisig) over keccak256(payload) must verify in Rust (`shekyl_pqc_verify` returns 0 per input); serve-credit-only txs exempt (signature lives on the vin, CEN-J10) | tx_pqc_verify.cpp:223–243; gate blockchain.cpp:4348–4356 | C | 1 | spec | [`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md); [`PQC_MULTISIG.md`](../PQC_MULTISIG.md) | RC-106, RC-108, RC-100 (gate half) ⇒ merged. **Inverse spot-check row** |

### 4.J Archival transaction families (all verdicts Rust-side; C++ marshals)

Serve-credit (per input; the whole-tx shape is CEN-H20):

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-J1 | The serve-credit vin is an opaque blob; only the Rust codec parses it (key extraction must succeed) | 5273–5280, 3893 idiom | C | 1 | spec | [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md) RF-D10 :772 (opaque `canonical_bytes`; the in-code "RF-D1" label is the kept/pruned-boundary decision — pointer corrected, §7) | |
| CEN-J2 | One pruned pass record per serve-credit vin, in vin order; each within `SERVE_CREDIT_PRUNED_MAX_BYTES` | 3724–3733, 5281–5285 | C | 1 | spec | [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md) RF-D1 :98 (kept/pruned boundary) | RC-110 ⇒ merged |
| CEN-J3 | Pair-epoch dedup: a (P, shard, E) with any existing pass row is rejected (one challenge per pair-epoch until the assignment issuer lands — reopen recorded) | 5287–5312 | C | 1 | spec | [`ARCHIVAL_PER_CHALLENGE_RECORD.md`](ARCHIVAL_PER_CHALLENGE_RECORD.md) §5.3; PC-D4/PC-D7 site comment with rule-21 reopen | RC-112 ⇒ merged. Block-level twin CEN-G7 |
| CEN-J4 | The named P must have a bond record | 5314–5319 | C | 1 | spec | gate-2 | RC-114 ⇒ split across CEN-J4–J7 |
| CEN-J5 | Claimed epoch ≥ E_first (join epoch + 1) | 5321–5328 | C | 1 | spec | gate-2 | |
| CEN-J6 | P must be `good_through` the claimed epoch | 5330–5335 | C | 1 | spec | gate-2 | |
| CEN-J7 | The credit must land by the epoch's close height (`current_height ≤ H_close`), and the challenge seal block (`H_seal`) must already be on-chain | 5337–5358 | C | 1 | spec | [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md); [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md); seal predicate Rust-authoritative | |
| CEN-J8 | P must hold the shard at the derived fire height `H_fire` (deterministic from seal hash, P, shard, E — WS-1 symmetric with the slash consumer), and the shard's frozen segment must exist at `H_fire` | 5376–5402 | C | 1 | spec | [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md) | RC-115 ⇒ split across CEN-J8/J9 |
| CEN-J9 | The challenged leaf index is **derived** (P, shard, E, prev-block-hash), never read off the vin; its chunk is read from the live consensus leaf table (frozen segments immutable); all-zero prev-hash refused; the serve-credit `prev_block_hash` binds the slot's parent (`block_hash(chain_height−1)`; pool records next-block-only, PC-D2) | 5404–5450; PC-D3 binding 3689–3722 | C | 1 | spec | [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md) RF-D6 :447; [`ARCHIVAL_PER_CHALLENGE_RECORD.md`](ARCHIVAL_PER_CHALLENGE_RECORD.md) §5.3 PC-D3/PC-D2 | RC-111 ⇒ merged. PC-D3's derivation is a load-bearing **interim** mitigation scheduled for deletion at the credit-wire cutover (2026-08-26 disposition, :134) — the rewrite spec must carry the reopen, not the mechanism |
| CEN-J10 | The full response verifies in Rust (`shekyl_archival_verify_serve_credit_vin`): record structure, P's countersignature (the vin-borne hybrid signature), retention-proof legs against the registry sub-root and leaf chunk | 5452–5474 | C | 1 | spec | [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md); [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) | RC-116 ⇒ merged |

Bond post (per tx; whole-tx shape CEN-H21; spend-subset FCMP verify shares CEN-I15's binding):

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-J11 | Hybrid pubkey length canonical (`PQC_HYBRID_SINGLE_KEY_LEN`); `p_canonical_id` must recompute from it | 4808–4826 | C | 1 | spec | [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | RC-117 ⇒ merged |
| CEN-J12 | `bond_spend_pk` coupling: JoinMarket must commit one (canonical length); every other kind must not carry one | 5115–5128, 4838, 4906, 5054 | C | 1 | spec | gate-4 §9.11 | RC-118 ⇒ split across CEN-J12/J13 |
| CEN-J13 | Debit arms (Unbond, HoldingsUpdate-drop; the fast-path belt CEN-G8 retired with its mechanism, C2-R1a) authorize only against the record's **committed** `bond_spend_pk`; credit arms (JoinMarket, HU-add, Rebond) authorize with the identity key `P_pubkey` (HU-add auth key must equal `P_pubkey`) | 4850, 4968, 4957–4962, 5099–5104, 5203–5210 | C | 1 | spec | GF-1: [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §9.6 :799 (RESOLVED 2026-06-16); [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §3.5 step 5 :419 | RC-122 ⇒ merged |
| CEN-J14 | JoinMarket semantics (Rust `shekyl_archival_verify_join_market_bond_post`): kind/shard-set shape, no debit, credit == bonded_total == bond_floor(holdings), record must not already exist | 5130–5148 | C | 1 | spec | gate-4 §3.5; floor from `config/consensus_constants.json` `archival_bond_floor_atomic` | RC-121 ⇒ split across CEN-J14/J16/J17/J18. DB-side p_id uniqueness is NOT a constraint (flag-0 put) — verify is sole enforcement (CEN-L14) |
| CEN-J15 | JoinMarket admission viability (D3/R3): per-shard r_market + freeze-height/presence facts at parent height must pass `shekyl_archival_check_bond_admission`; drops deliberately ungated | 5150–5201 | C | 1 | spec | [`ARCHIVAL_SIM_ECONOMICS_VERDICT.md`](../completed/ARCHIVAL_SIM_ECONOMICS_VERDICT.md); `shekyl-archival-retention::admission` | |
| CEN-J16 | Unbond semantics (Rust): full exit only (debit == record total, post-total 0, empty holdings), release cooldown elapsed from the P2B-8 last-served anchors, slash settlement current through the anchor | 4832–4897 | C | 1 | spec | gate-4 §3.5 debit path; `config/consensus_constants.json` `release_cooldown_epochs` | |
| CEN-J17 | HoldingsUpdate: add arm = exactly one shard, +FLOOR credit, good-standing record; drop arm = exactly one shard removed, −FLOOR debit, grace-tail/age facts verified (unfrozen shard pinned to the longest horizon) | 4900–5046 | C | 1 | spec | gate-4 §3.4–3.5 | |
| CEN-J18 | Rebond (Rust): interval-log preconditions (single open interval, headroom bound), credit against identity key | 5049–5105 | C | 1 | spec | gate-4 §3.4 (P2B-9 pins 4–6) | |

Reward emission (per tx; whole-tx shape CEN-H22):

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-J19 | The emission vin's opaque blob must parse (Rust extract: claimant P id + claimed epochs, ≥ 1); failure rejects | 3888–3902 | C | 1 | spec | [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) | RC-124 ⇒ merged |
| CEN-J20 | The emission slot's hybrid key must derive the vin's `P_canonical_id` (so the tx-wide hybrid signature over the slot is P's) | 3904–3921 | C | 1 | spec | E3 §8.0.2 (C-1) | RC-125 ⇒ merged |
| CEN-J21 | referenceBlock/curve-tree context as CEN-I10–I13, required even with zero fee inputs (the vin's membership-only backing proof verifies against that root) | 3942–3980 | C | 1 | spec | [`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) | |
| CEN-J22 | The signable hash is the prefix hash of the tx **with the emission vin removed**; every property the exclusion loses is re-bound by the Q1 auth message and the reward commit set. Tx-level PQC still covers the full prefix | 3982–3994 | C | 1 | spec | E3 (F-C1c) | RC-129 ⇒ merged |
| CEN-J23 | Every claimed epoch must have a frozen budget row (closed, unpruned epoch); the as-of-E snapshots are gathered per epoch | 3996–4034 | C | 1 | spec | [`ARCHIVAL_BUDGET_SCHEDULE.md`](ARCHIVAL_BUDGET_SCHEDULE.md); [`EMISSION_CLAIM_BUILDER.md`](EMISSION_CLAIM_BUILDER.md) | RC-128 ⇒ split across CEN-J23–J25 |
| CEN-J24 | The reward commit set is the loud (non-zero) vouts in vout order (mask ‖ amount_le ‖ one-time key); zero-amount vouts are ordinary change; reward total is Rust-checked-summed (overflow rejects) | 4036–4084 | C | 1 | spec | E3 §8.0.2 field 7; [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) §4 | |
| CEN-J25 | The coarse Rust verify (`shekyl_emission_vin_verify`) decides §7.1 claims 1–5 (claim-window/max-age, work arithmetic vs the frozen snapshots, reward total equality), the membership-only backing proof, and the hybrid auth gate — any non-OK rejects; `vout_reward_sum` is the inflation-audit operand | 4086–4118 | C | 1 | spec | [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §7.1; [`ARCHIVAL_REWARD_ARITHMETIC.md`](ARCHIVAL_REWARD_ARITHMETIC.md); `config/consensus_constants.json` | this branch mints coins — flagged load-bearing at the site |
| CEN-J26 | Fee-input FCMP++ proof: absent ⇔ zero fee inputs; present ⇒ verifies over the `txin_to_key` subset exactly as CEN-I15; fee inputs: empty offsets, unspent KIs; pseudoOuts match spend count | 4120–4184, 3566–3588 | C | 1 | spec | E3 §7.1 step 7, Q11 | RC-126 ⇒ merged |

### 4.K Reorg / alternative chains

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-K1 | An alt block claiming height 0 is rejected | 2222–2228; difficulty-side sentinel return 1559–1563 (CEN-D5/D6) | C | 4 | none | — | RC-134 ⇒ merged with a recorded judgment disagreement: RC read this bucket 1 (rule 60 + comment :1553–1558); no record *names* alternative-genesis rejection, so it stays 4 under the §2 bar |
| CEN-K2 | Alt-chain linkage: the stored alt chain must connect to the main chain at the claimed height with matching hashes (asserted while rebuilding) | 2153–2205 | C | 4 | none | — | |
| CEN-K3 | An alt block already stored as an alt block is rejected | 2461; DB belt `MDB_NODUPDATA` src/blockchain_db/lmdb/db_lmdb.cpp:4736–4740 | C | 4 | none | — | RC-148 ⇒ merged (DB belt site added) |
| CEN-K4 | Alt blocks are accepted into storage after: version (CEN-B1 at ideal-version-for-height), attestation (CEN-B4), timestamp FTL + strict median over the newest-11 window (CEN-C1/C2 per C2-R3), checkpoint, PoW at alt difficulty (CEN-D1/D5), and **prevalidate**-only miner-tx checks; `validate_miner_transaction`, `check_tx_inputs` and the curve-root check are deferred to promotion | 2214–2509 | C | 4 | none | — | the deferral is the reorg path's central unexamined design decision. §3.5 table; §10 R1 |
| CEN-K5 | Promotion re-validates every block through the full 4-arg main-chain path (all §4.B–§4.J rules); any failure rolls back to the pre-switch chain and discards the failing alt suffix | 1425–1462 | C | 2 | ratified | **RULED C2-R1b (ratified 2026-09-03)** — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b | Q1a: promotion re-validation ratified as the containment for the admission subset; prior notes: RC-138 merged |
| CEN-K5b | Each promoted block's credit-wire attestation witness is re-supplied from the hash-keyed alt table (and each demoted block's is captured off its height row before the pop), so the witness survives reorgs in both directions | 1436–1438, 1411–1418, 2469–2477 | C | 1 | spec | [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) §3 (CW-2) | |
| CEN-K6 | Reorg trigger: alt cumulative difficulty **strictly greater** than main (equal stays), or an alt block matching a checkpoint forces the switch **Ruled**: strictly greater switches, equality keeps, checkpoint match forces; the discard-vs-readmit asymmetry (K7) is the flip-flop terminator — a checkpoint can promote a LIGHTER chain. | 2481–2504 | C | 2 | ratified | **RULED C2-R1b (ratified 2026-09-03)** — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b | Q1a/Q1b: the comparison's ONE implementation is `shekyl-difficulty::fork_choice` behind `shekyl_difficulty_fork_choice`; C++ marshals and consumes the verdict; shared vectors `FORK_CHOICE_V1.json`. Prior: RC-136/137 merged |
| CEN-K7 | Demoted main-chain blocks re-enter as alt blocks (witness carried); failure there is logged, not a switch failure; on a discarded chain they are dropped | 1404–1419, 1465–1486 | C | 2 | ratified | **RULED C2-R1b (ratified 2026-09-03)** — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b | Q1a: demote-re-entry on difficulty switches, discard on checkpoint-forced switches — ratified as intentional mechanism (the flip-flop terminator); prior: RC-139 merged |
| CEN-K8 | Alt bookkeeping's `already_generated_coins` is a documented approximation (coinbase-paid, not subsidy); nothing consensus-bearing reads it; promotion re-reads the ledger, and the post-reorg miner notification reads DB cumulative supply, not the alt copy | 2277–2303, 1504–1524 | C | 2 | ratified | **RULED C2-R1b (ratified 2026-09-03)** — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b | Q1a: ratified-and-kept — approximation by construction, nothing consensus-bearing reads it, deleting the field would change the persisted `alt_block_data_t` layout (rule 42 fence); prior: RC-140/141 merged |
| CEN-K9 | Alt-block pool-supplement txs must pass NIC and enter the main pool (`relay_method::block`) or the alt block is rejected | 2378–2420 | C | 4 | none | — | |
| CEN-K10 | Pool `add_tx` with `kept_by_block` (block/reorg-sourced txs): input-check failure stores the tx anyway as `verification_impossible` (it may become valid again after further reorg) | tx_pool.cpp:305–357 | C | 4 | none | — | RC-158 ⇒ merged with a recorded flag disagreement: RC flagged P (the arm cannot itself fork the chain); kept C per CEN because the arm participates in alt acceptance — CEN-K9 rejects the alt block when pool insertion fails, and this arm is what makes an input-check failure a stored tx rather than that rejection. Consensus will re-check at connect (CEN-K5) |

### 4.L Storage layer (constraints that reject chain data at write time)

[SANITY]-class corruption guards and IO-error guards are counted once as CEN-L13, not row-per-throw; rows here are chain-rule enforcement. All paths `src/blockchain_db/`.

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-L1 | Key-image uniqueness at block connect is enforced **solely** here: `add_spent_key`'s `MDB_NODUPDATA` put throws `KEY_IMAGE_EXISTS` (covers chain-wide and intra-block duplicates in one txn), caught at blockchain.cpp:6397 → block rejected. The pre-DB `check_for_double_spend` is dead (§5) | lmdb/db_lmdb.cpp:1411–1425 | C | 4 | none | — | RC-144, RC-150, RC-99 (enforcement note) ⇒ merged. Recorded judgment disagreement: RC read this bucket 1 (FCMP nullifier); the *commitment* is CEN-I7's (bucket 1) — this row's open question is the **placement** (validation completed by a side effect of the write path, §6). Inverse spot-check row. §10 R8 |
| CEN-L2 | A connecting block's `prev_id` must exist and sit at height−1 — wrong-height throws `BLOCK_PARENT_DNE` (:962); missing parent throws `DB_ERROR` (:959); genesis exempt. Block blobs are appended at `m_height` (`MDB_APPEND`) so stored height is strictly increasing | lmdb/db_lmdb.cpp:951–963, 973–978 | C | 4 | none | — | RC-145, RC-146 ⇒ merged |
| CEN-L3 | Duplicate block hash (`BLOCK_EXISTS`) and duplicate tx hash (`TX_EXISTS`) reject at write | lmdb/db_lmdb.cpp:948–949, 1071–1074 | C | 4 | none | — | RC-143, RC-147, RC-174 ⇒ merged. Belt behind CEN-A1/G1 — and for the **miner tx** (absent from `tx_hashes`, uncovered by CEN-G1) `TX_EXISTS` is the *only* connect-time uniqueness check |
| CEN-L4 | The base `add_block` recomputes the block hash (identity never trusted) but stores contained txs under the header's claimed hashes verbatim — content/hash agreement lives upstream (CEN-G2); `blk.tx_hashes.size() == txs.size()` is asserted at store time | blockchain_db.cpp:459, 477–480; count belt :455–456 | C | 4 | none | — | RC-175 ⇒ merged. Recorded absence, §6 |
| CEN-L5 | DB input-type whitelist duplicates CEN-H5 at write time; unknown bond-post kinds fatal | blockchain_db.cpp:398–402, 363–366 | C | 4 | none | — | |
| CEN-L6 | Every stored output must carry an outPk commitment and yield an output pubkey; coinbase/emission loud amounts store as amount-0 plus the real commitment | blockchain_db.cpp:424–434; lmdb/db_lmdb.cpp:1274–1277, 1361–1368 | C | 4 | none | — | RC-149 ⇒ merged with a recorded judgment disagreement: RC read the amount-0 indexing bucket 1 (amount-0 CT design); no record names the indexing choice, stays 4 |
| CEN-L7 | Archival connect-writers are fatal verify-backstops (never soft-skip): emission claim requires the bond record, re-runs the claimed-epochs dedup and claimability (already-claimed or unclaimable epoch aborts the connect); bond folds' Rust verdicts abort on failure (missing record, fold fail, holdings invariant breach) | blockchain_db.cpp:301–395; lmdb/db_lmdb.cpp:6428–6484, 6541–6597, 6746–6789 | C | 1 | spec | WS-2 journaled check-and-set (E3); [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) (pinned 2026-06-07) | RC-176, RC-179 ⇒ merged. Checkpoint-fast-path belt |
| CEN-L8 | Epoch close at each settlement boundary: Rust fold freezes budget(E), r_market and sigma-work rows; accrual-sum overflow aborts (never mints); settlement `(passes, issued)` fold refusal aborts the same `add_block` write txn | lmdb/db_lmdb.cpp:8326–8442; hook blockchain_db.cpp:654–655 | C | 1 | spec | [`ARCHIVAL_BUDGET_SCHEDULE.md`](ARCHIVAL_BUDGET_SCHEDULE.md); [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md); [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §3.5 | RC-177 ⇒ merged. **The DB is the enforcement site** |
| CEN-L9 | Slash processing at each height: missed-baseline slashes apply via Rust interval verdicts; no-bond / shard-not-held / interval-decision-fail / bonded-underflow / burned-overflow is FATAL | lmdb/db_lmdb.cpp:6193, 5911–6042 | C | 1 | spec | [`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](../completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md) §1 (m=11/n=13, genesis-frozen); [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md); `config/consensus_constants.json` | RC-178 ⇒ merged |
| CEN-L10 | Segment freezes at each height: first-crossing rule over the append-only leaf count; a frozen segment's layer-2 sub-root must exist in the tree; the registry row is CREATE-only (`MDB_NOOVERWRITE` — a second freeze of the same shard is FATAL, the O-2 overwrite adversary refused) | lmdb/db_lmdb.cpp:7978–8026; CREATE-only :8528–8536 | C | 1 | spec | [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md) §5.2; O-2 CREATE-only; `config/consensus_constants.json` `segment_leaf_count` 25992 | RC-173 ⇒ merged. **DB-only** — no Blockchain duplicate check |
| CEN-L11 | Curve-tree growth per block: every accepted output becomes a leaf (`shekyl_construct_curve_tree_leaf` over key ‖ commitment ‖ PQC leaf hash), added **pending** with a maturity height. The tree-**grow** verdicts abort on failure, and since 2026-09-04 so does the leaf-**construct** verdict (it previously did not) — a false return at :586–589, and the two `continue` arms beside it, used to drop the output from the tree with no verify-time twin. All three now abort (2026-09-04); they were unreachable through admission even before, so this was a latent surface rather than the live loss the row implied — CSR §5.4.1 CEN-L11 carries the walk; **re-reviewed CHECKED-CONFORMANT at `ab4693d0e`** (2026-09-04, containing PR #609's merge) | blockchain_db.cpp:500–617; lmdb/db_lmdb.cpp:8964–9166 | C | 1 | spec | [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md); [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | soft-skip = a deterministic but permanently unspendable output; FOLLOWUPS row **closed 2026-09-04** when the arms were made fail-closed (owner repointed here) |
| CEN-L12 | Deferred-insertion maturity IS the spend-maturity rule: coinbase leaves enter the tree at height+60, all other outputs at height+`CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (10); `tx.unlock_time` plays **no** role in when an output becomes spendable | blockchain_db.cpp:531–575; drain :583 (impl lmdb/db_lmdb.cpp:8589) | C | 1 | spec | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §7 step 1 ("Maturity is enforced by universal deferred tree insertion") | the spec's "staked: max(effective_lock_until…)" arm does not exist in code (claim-era, retired) — §7. Third leg of the unlock_time triple-divergence (§6); CHECKED-CONFORMANT with CEN-L11 since 2026-09-04 (CSR §5.4.1) |
| CEN-L13 | Corruption/desync guards throughout the write and pop paths (serve-credit re-parse, bond-counter overflow, journal-vs-tip belts, trim bounds, pruned-pop refusal, …) abort the operation rather than storing inconsistent consensus state | blockchain_db.cpp / lmdb/db_lmdb.cpp per traversal | C | 4 | none | — | counted as one row: sanity class, not independently ratifiable chain behavior |
| CEN-L14 | DB-absent uniqueness (deliberately verify-side only): serve-credit pass bits, bond records (JoinMarket p_id), budget accrual rows, witness rows, curve-root heights are flag-0 overwrites | lmdb/db_lmdb.cpp:5168–5181, 5591–5615, 4916–4928, 9663–9672, 9618 | C | 4 | none | — | recorded absences; the PC-D4 comment at blockchain_db.cpp:775–786 records the bug class this tolerance once masked. §10 R8 |
| CEN-L15 | `if (blk.major_version >= 4)` cumulative-RCT accumulation in `block_info` never runs (live major is 1); `bi_cum_rct` therefore holds this block's RCT count only — a dead Monero-v4 (RCT-era) dispatch arm on the write path | lmdb/db_lmdb.cpp:988–998 | C | 3 | — | rule 60: `RCTType*` named in the deleted-from-construction list; "delete the dead branch" for Monero-era version dispatch | [m] RC-180 ⇒ minted at RC's bucket. §10 R5 executes |

### 4.M Mempool admission (the `kept_by_block` axis)

`kept_by_block = (tx_relay == relay_method::block)` (tx_pool.cpp:229) — rows it exempts are **policy**. The discriminator itself is the census's classification instrument (RC-151's meta-rule), stated here once rather than as a row.

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-M1 | A tx already in the pool (broadcasted) or chain is accepted idempotently without re-verification | cryptonote_core.cpp:999–1009 | P | 4 | none | — | |
| CEN-M2 | Pool admission runs the full NIC set (CEN-H*) at the current HF version, cached per HF (`nic_verified_hf_version`; skipped in `add_tx` when the cached version matches; cache correctness depends on hf not changing under it) | tx_pool.cpp:236–237; tx_verification_utils.cpp:265–284 | C | 4 | none | — | RC-71, RC-161 ⇒ merged. Consensus rules, pool site |
| CEN-M3 | Relay fee floor: fee ≥ 98% of quantized `weight × fee_per_byte`, where fee-per-byte = `0.95·base_reward·ref_weight/median²` (integer) off the current reward/medians; unpayable-reward state rejects all; `kept_by_block` exempt — **no consensus fee floor** | tx_pool.cpp:243–259; blockchain.cpp:4363–4413 | P | 4 | examined-disposition | [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) §8 row P2 :1309 (examined on the **submit path**: C + D re-gate F34, KAT against `check_fee`); the 2026-08-16/17 era-max ruling (decision log :4684–4690) derived the **wallet-side** fee ceiling `Fh = 14,000,000` ("KAT-pinned — not a literal") — it is not a daemon acceptance rule (verified: no such constant in `src/`), so it bounds this row's *machinery* without ratifying it | RC-152, RC-153 ⇒ merged. Demoted from CEN's bucket 2 under the §2 bar: the 0.95 factor, quantization mask, reference weight and 2% buffer have no examination record as choices. §10 R2. **R2 DEFERRED** (Rick 2026-09-03, §10) pending FL-R12′ |
| CEN-M4 | Relay cap on `tx.extra`: ≤ `MAX_TX_EXTRA_SIZE` (24 576); `kept_by_block` exempt — consensus side has no tx_extra bound beyond CEN-H1 | tx_pool.cpp:261–269; cryptonote_config.h:353 | P | 4 | examined-disposition | bound frozen [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §10 :791; [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) §8 row P3 :1310 (submit path) | RC-154 ⇒ merged. Demoted from CEN's bucket 2 under the §2 bar. Canonical-form arbitration deferred to the credit-wire lane (per the SA index row) — deferred, not done. **R2 DEFERRED** (Rick 2026-09-03, §10) pending FL-R12′ |
| CEN-M5 | Relay ban on any nonzero `unlock_time`; `kept_by_block` exempt (a height-locked spend can still be in a block) | tx_pool.cpp:271–278 | P | 2 | ratified | [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) §8 row P1 :1308; [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) :888–891 (the two-layer unlock ban); decision-log :4325–4327 (rationale) | RC-155 ⇒ merged (RC's bucket-3 reading — "a relay ban on height-locks too" — is superseded by the located two-layer ratification). Second leg of the unlock_time triple-divergence (§6) |
| CEN-M6 | Relay-side double-spend pre-check against the chain (`have_tx_keyimges_as_spent`); `kept_by_block` exempt | tx_pool.cpp:283–294 | P | 4 | none | — | RC-157 (chain half) ⇒ merged. Consensus enforcement is CEN-I7 + CEN-L1; the `kept_by_block` skip is the popped-block path (TODO comment :282) |
| CEN-M7 | Pool-side key-image conflict tracking (`insert_key_images`) prevents two pool txs spending one image in the same relay category | tx_pool.cpp:337, 496 | P | 4 | none | — | RC-157 (pool half) ⇒ merged |
| CEN-M8 | FCMP++ verification cache: pool stores `H(proof ‖ referenceBlock ‖ key images)`; block connect skips only the proof re-verify when the hash still matches | tx_pool.cpp:485–494, 1735–1743; blockchain.cpp:4592–4625 | C | 1 | spec | [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §71–§72.1 (embargo-load-bearing placement) | |
| CEN-M9 | Engine-attested local submit (`insert_attested_tx`): a tx the Rust engine verified enters the pool without C++ re-verification; the certificate gate lives in the submit FFI; consensus still re-validates at block connect | tx_pool.cpp:550–640; src/rpc/daemon_submit_ffi.cpp:577 | P | 1 | spec | [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) §3–§4 | |
| CEN-M10 | Pool lifetime/eviction: non-`kept_by_block` txs expire at `CRYPTONOTE_MEMPOOL_TX_LIVETIME` (3 days), `kept_by_block` at the longer alt-block lifetime; stale-reference and weight-cap pruning (`m_txpool_max_weight`) evict lowest fee/byte first | tx_pool.cpp:1040–1059, 532 | P | 4 | none | the 3-day livetime is consumed as given by the submit round ([`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) :942–943 re-relay bound) — consumption, not examination | RC-160 ⇒ merged. Pool weight cap and livetime never ratified as policy choices. §10 R2/R7. **R2 DEFERRED** (Rick 2026-09-03, §10) pending FL-R12′ |
| CEN-M11 | Zero-fee txs are never flagged for relay (`m_relay` set only when fee > 0); consensus permits zero-fee (serve-credit txs are zero-fee by CEN-H20) — the attested/block paths carry them | tx_pool.cpp:519–521 | P | 4 | none | — | |

---

## 5. Dead validation surfaces (outside the §3 denominator)

Caller-less **functions** are recorded here, not as rows; dead **branches
inside live functions** are rows (CEN-F12, CEN-L15) because a rewrite
walking the live function will meet them. Rule-60 material throughout.

1. **The whole ring-spend validation path is caller-less.**
   `Blockchain::check_tx_input` (:4532) — with `scan_outputkeys_for_indexes`
   (:256) and the spend-side `is_tx_spendtime_unlocked` gate inside it — has
   zero call sites. Ring/unlock spend validation survives as text only.
   *(RC-98 ⇒ this record; rule 60 names the ring path.)*
2. **`is_tx_spendtime_unlocked` (:4505) and `get_adjusted_time` (:5480) are
   off the acceptance path.** Verified at the pin: the only live caller of
   `is_tx_spendtime_unlocked` is the RPC-serving
   `get_output_key_mask_unlocked` (:2681); the other caller is dead
   surface #1. RC rowed these (RC-80, RC-32) as consensus; the merge
   resolves them here — the unix-time arm and the `+(WINDOW+1)*T/2`
   time projection constrain nothing a block or tx can do. The *stored*
   `unlock_time` semantics they would have interpreted are inert by
   CEN-L12. *(RC-32, RC-80 ⇒ this record.)*
3. **`check_for_double_spend` (:3124) is dead** — its only call site is
   commented out (:6024–6030); live enforcement is CEN-L1.
   *(RC-99 ⇒ CEN-L1 note + this record.)*
4. **The 2-arg `handle_block_to_main_chain` (:3100) is caller-less.** Every
   path uses the 4-arg form (`add_new_block` :6655, promotion :1438,
   rollback :1370). Both walks converged: one live rule set, one dead
   forwarder.
5. **HF version dispatch is dead from genesis** (detail in the archived
   CEN §5.4, carried by reference — the enumeration there was verified by
   the seven-re-reader pass): all eleven `HF_VERSION_*` constants are 1;
   every `>=` arm always-taken, every else-arm unreachable; four constants
   wholly unreferenced in production code; the
   `should_ask_for_pruned_data` refusal (`HF_VERSION_SMALLER_BP+1` →
   `UINT64_MAX`) means this node never requests pruned spans — a dead
   dispatch with a live behavioral consequence. Live FOLLOWUPS row
   (owner repointed here).
6. **`txin_to_script` / `txin_to_scripthash`** exist only to be rejected
   (CEN-H5) — variant fossils. **Unused ring-era locals** in
   `check_tx_inputs` (`sig_index` :3444, `pubkeys` :3532) ride along.

---

## 6. Cross-cutting findings (union of the walks; design-round input, not rulings)

1. **Enforcement placement is part of the spec.** The block-connect KI
   double-spend check lives only in the storage layer (CEN-L1, an LMDB
   exception caught two frames up); the DB stores txs under claimed hashes
   verbatim (CEN-L4, agreement argued at CEN-G2); five archival uniqueness
   rules have no DB constraint at all (CEN-L14); `HardFork::add`'s reject
   verdict is discarded at the DB call site (CEN-B3). The rewrite must
   *decide* where each rule lives; today's placement is an accident of the
   write path. (§10 R8.)
2. **The unlock_time triple-divergence.** One field, three stories:
   consensus accepts any height-form value < 500 000 000 (CEN-H16, ratified);
   relay refuses any nonzero value (CEN-M5, ratified); the curve tree
   ignores the field entirely and applies fixed maturities 60/10 (CEN-L12).
   Each layer is individually recorded; the *composition* — a field that is
   consensus-legal, relay-illegal, and semantically inert — has no single
   owner. Survey A's U-2 ("two spendability mechanisms") resolves to this:
   the tree is the enforcer; the inherited per-output unlock check survives
   only on dead surfaces (§5.1/§5.2). The rewrite should carry **one**
   story. (§10 R5.)
3. **Fees are pure relay policy** — a block may include a zero-fee tx
   (CEN-M3 `kept_by_block` exempt); serve-credit txs rely on this
   (CEN-M11). Whether a consensus fee floor is wanted is R2 material.
4. **Checkpoint machinery is live with empty data** (CEN-E1/E2/E5); the
   compiled-hash fast path that skipped PoW + FCMP when populated
   (CEN-E3) was **deleted by C2-R1a** (2026-09-02) together with the
   GF-1 belt (CEN-G8) that existed because of the skip. (§10 R1;
   [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §3.)
5. **The reorg acceptance design has no examined-decision record
   anywhere** — steering searched decision log, docs/design, docs/completed
   (terms: reorg, alternative chain, alt block, switch_to_alternative,
   cumulative difficulty, prevalidate); peripheral records only:
   [`CT2_DRAIN_ORDER.md`](CT2_DRAIN_ORDER.md) :422 (reorg engine as test
   vehicle), [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
   :290–293 (archival-leg `ARCHIVAL_REORG_DEPTH_BLOCKS = 720` + revert-order
   pins), and a deliberately-preserved RPC alt-block quirk
   ([`DAEMON_RPC_KV_CUTOVER.md`](DAEMON_RPC_KV_CUTOVER.md) :563). Meanwhile
   the path is interleaved with Shekyl-specific state (CEN-K5b witness
   re-supply, archival pop-side belts). Survey A U-3's question — what a
   reorg does to serve credit, challenge assignment, slash watermarks
   across an epoch boundary — is unanswered on record. (§10 R1.)
6. **Two-site drift risks, recorded so the rewrite collapses them
   deliberately:** tx-version bound stated twice in different machinery
   (CEN-H2 table vs CEN-I3 hardcode — live FOLLOWUPS row); `CTTypeNull`
   rejection at three sites (CEN-H15); the pool-vs-connect halves of the
   weight limit (CEN-H3). Not drifted today.
7. **`verify_block_attestation` runs before PoW on both paths**
   (5738 < 5818; 2253 < 2347) — free pre-cutover (empty witness), a DoS
   surface post-cutover; the Phase-5 ordering constraint (attestation
   behind PoW before population activates) is pinned at both sites and has
   a live FOLLOWUPS row (owner repointed here).
8. **FAKECHAIN/regtest levers compiled into consensus paths** (CEN-I2's
   carve-out block, CEN-B5's root-check skip, CEN-D7, CEN-D3's env
   override): enumeration input for the rewrite's test-seam design.
   (§10 R9.)
9. **`docs/MERKLE_TREE.md` documents the curve tree, not the block tx-hash
   tree its name implies** (grounded negative, confirmed by both CEN and
   the Appendix-A pass; its :201 still narrates the retired staked-arm
   maturity). Known residue (pruning-taxonomy bucket-1 list); census
   cross-reference only.
10. **The staking consensus is interleaved, not layered** (Survey A O-1:
    256 archival/bond/shard references inside `blockchain.cpp`). A rewrite
    plan that assumes it can port the "Monero part" and keep the "Shekyl
    part" separately is wrong at the outset.
11. **Bucket asymmetry is the argument for the census** (Survey A O-2,
    quantified by the merged set): 87 rows are Shekyl-spec'd; 14 are
    ratified inherited; 70 carry open questions. Most of the inherited
    consensus surface has no specification other than its own source.
    Survey A's O-4 counterweight also stands: the bucket-1/2 surfaces
    (DAA, economics KATs, FCMP++/PQC, archival) are in good shape and the
    census *closes* them rather than reopening them.
12. **Every bucket-4 item is cheapest now** (Survey A O-3): pre-genesis
    they are free; post-genesis they are permanent. This deadline applies
    whether or not the rewrite happens — it is what sequences §10.

---

## 7. Decision log — where the C1 merge met the tree

The RK convention: what an input claimed vs what the pinned tree contains.
Behavioral statements in §4 follow the code; divergences are design-round
input, not fixes.

1. **MTP is a three-way split, worse than either input recorded** (CEN-C2).
   CEN §6.3 found doc-strict vs code-nonstrict; the C1 pass additionally
   found the spec-conformant **strict** Rust predicate
   (`is_above_mtp`, timestamp.rs:64) exported with zero production callers.
   Ratification premise refuted at :5519 (`b.timestamp < median_ts` is the
   only reject). Adjudicated by steering; class `ratified-premise-refuted`;
   FOLLOWUPS row added; early R3 ruling + boundary test flagged. Nothing
   fixed here — not the code, not the doc, not the unwired predicate.
2. **F12/RC-45 dead-branch reading confirmed at the pin** (CEN-F12): the
   caller passes `m_hardfork->get_current_version()` at :6272; the
   `version == 3` arm cannot run. CEN's demotion stands; #583's in-PR
   correction of RC-45 ("keys off HF version") cited.
3. **RC-9 vs CEN-B2 resolved as both-half-right** (CEN-B2): `do_check`
   does contain `voting_version >= current` (RC's predicate), and the
   0→1 vote normalization plus current==1 make it unfailable (CEN's
   effect). Verified at hardfork.cpp:41–50, 109–113.
4. **RC-32/RC-80 are not on the acceptance path** (§5.2): the only live
   `is_tx_spendtime_unlocked` caller is the RPC-serving
   `get_output_key_mask_unlocked` (:2670–2682). RC's consensus flag on
   those rows does not survive contact with the caller graph.
5. **The Fh = 14,000,000 ceiling is wallet-side** (CEN-M3): the decision-log
   :4684–4690 ruling covers the fee-tier cap "on every tier including
   Custom"; no such constant exists in `src/` (grepped). It is evidence
   about the fee machinery's examination, not a daemon acceptance rule —
   so no consensus/policy row was minted for it.
6. **Survey A's "A3 fee round" has no locatable record** (CEN-F14b, CEN-M3):
   searched docs/completed/, docs/design/, the decision log. The locatable
   trail is the scaling KAT + the DSV submit-path exam + the Fh derivation.
   A remembered round without a findable record does not clear the §2 bar.
7. **DAA_LWMA1.md names the alt-difficulty consumer but does not ratify the
   stitch** (CEN-D5): :1758–1769 warns on the consumer's off-by-one;
   the main-prefix++alt-suffix window construction itself has no keep
   record. RC's bucket-1 reading recorded as the dissent.
8. **checkpoints.cpp verified as steering described** (CEN-E1): zero
   compiled-in checkpoints (`init_default_checkpoints` empty on all
   networks), the single `ADD_CHECKPOINT` (:223) is the JSON-loader loop,
   no DNS machinery in the file.
9. **CEN-K10's flag disagreement kept at C** with RC's P reasoning recorded
   in the row: the arm participates in alt acceptance (CEN-K9 rejects the
   alt block when pool insertion fails).
10. **Three broken pointers fixed in merged rows** (from the Appendix-A
    payload, matching CEN §6.5): loud-vout rule lives in
    `REWARD_EMISSION_LEG.md` §5.5 :494–503, not `REWARD_EMISSION_VIN_PLAN.md`
    §4 (CEN-H14); the opaque-vin-blob ruling is RF-D10 :772, RF-D1 :98 is
    the kept/pruned boundary (CEN-J1/J2); the frozen-segment read-point is
    `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.12 :2121, not §6.2
    (CEN-F19).
11. **CHANGELOG pointers re-located at the pin** (that file changed between
    the walkers' sha and the pin): MTP/FTL constant swap :14858–14863
    (was cited :14844/:14849); penalty 81-vector KAT :1178 (was
    :1152–1160); Decision 14 :26404–26407 (was :26390); Decision 13
    :26409–26411.
12. **FA-6's sign-off is S1–S4/S6–S9 signed + S5 ratified** (2026-06-02) —
    the payload's "S1–S9 signed" shorthand holds in effect; recorded
    precisely in CEN-H12's evidence.
13. **Stale in-code narrations carried, not fixed** (from CEN §6.10,
    re-confirmed): the F-B1b `bl.major_version` comment at :6293–6306
    contradicted by the version-less calls below it (CEN-G11); the
    `if (version == 3)` gate reading as a tx-version check (CEN-F12);
    `ARCHIVAL_CREDIT_WIRE.md` §3's stale enforcement-status paragraph
    (CEN-B4); `FCMP_PLUS_PLUS.md` §7's three drifts — header-vs-table
    root read (CEN-I12), the un-evidenced key-image y-normalization step
    (open question, §3.4), the retired staked-maturity arm (CEN-L12).
14. **"Assert" language on the difficulty guards corrected against the
    macro** (PR-586 review round). `CHECK_AND_ASSERT_MES` is
    log-and-return-false (`contrib/epee/include/misc_log_ex.h:396`): the
    zero-difficulty guards at 5766/2324 **reject the block**, and the
    height-0 alt-difficulty arm at 1559–1563 **sentinel-returns
    difficulty 0** into that guard — no process abort exists on this
    path (the :5763 FIXME's "can also assert" is the same loose usage).
    CEN-D5/D6 and CEN-K1's site note were reworded; CEN-D1 gained the
    CEN-E3 fast-path cross-reference. Behavioral content of the rows is
    unchanged.
15. **C2-R3 ruled the timestamp batch — the first C2 rulings land in the
    census** (2026-09-01, [`CONSENSUS_C2_R3_TIMESTAMPS.md`](../completed/CONSENSUS_C2_R3_TIMESTAMPS.md),
    ratified by Rick). Entry #1's three-way MTP split is resolved on the
    merits: strict `>` re-ratified on fresh ground (the pinned LWMA-1
    sources are boundary-indifferent; commitment 3 arbitrates), the alt
    window truncated to the newest 11 (the whole-alt-chain median with
    epee even-window averaging is deleted), the miner-template floor is
    `median + 1`, the bootstrap carve-out is replaced by genesis-timestamp
    window padding, and FTL now runs at alt admission. CEN-C2/C3 →
    bucket 2 `ratified`; CEN-C1 gained the alt rejection site (§11.2);
    counts updated in §3/§3.1. Two surfaces the C1 rows had not named
    were found and folded by the round: the Jagerman template bump
    (self-consistent only under non-strict; now `median + 1`) and the
    alt path's uncapped window. Four losing-leg behaviors observed
    red-first in `core_tests`; the shared vectors
    `docs/test_vectors/MTP_BOUNDARY_V1.json` pin C++ and Rust to one
    rule. The pre-change stressnet was measured **genesis-only** (all
    estate peers at height 1, 2026-09-01), so the consensus change
    invalidates no chain with a future.
16. **CEN-I12's anchor source reconciled — the §7 step-2 prose was stale
    narration of a dead read path** (2026-09-04; ruled by Rick on merge).
    Entry 13 carried "header-vs-table root read" as a drift. `git log -S`
    settles which side was the spec: the section was split from its first
    commit (`fb047fdc20`, 2026-04-03 — pseudocode 2a named the per-height
    record, the prose two paragraphs below narrated the
    `get_block_header(rv.referenceBlock).curve_tree_root` read the code
    performed then); `292c00aff7` (2026-04-13) moved the code to the record
    because FAKECHAIN test blocks carry placeholder headers without touching
    the doc, and none of the later doc edits — four through the 2026-04-15
    banner, thirty to date (`git log 292c00aff7..d9d27c752 --
    docs/FCMP_PLUS_PLUS.md`) — reconciled the two, so the prose narrated
    dead code for five months. **Ruling:** the
    anchor is the curve-tree root *as it stands after `referenceBlock`
    connects* — a state property, of which the header field and the
    per-height record are two witnesses bound to each other by CEN-B5; the
    verifier reads its own computed record (the fact it checked the header
    against), the prover reads the header under the same binding
    (`CURVE_TREE_CLIENT.md` §3.3). The rejected alternative — the header as
    the normative source — would make the verifier anchor on a claim it has
    itself verified against the fact, and would need every block's header
    checked on every nettype, which B5's FAKECHAIN skip denies today. The
    in-code FAKECHAIN rationale is a consequence, not the reason, and
    carrying it as the reason is what made P0f slice 7's promotion
    rule-71-adjacent: the witnesses differ exactly where B5 is skipped, so
    R9 is the only thing that makes the choice observable, and only in
    tests. Nothing in C++ changes; the comment stays as a true statement of
    a consequence. **Found, not ruled, one row over:** step 2b/2c's
    pseudocode says `curve_trees_tree_depth ==` the depth at
    `referenceBlock` while the code (CEN-I13, CHECKED-CONFORMANT)
    range-checks `[1, current depth]`; at the FFI boundary the claimed
    depth must equal the proof's embedded depth (`proof.rs`,
    `proof.tree_depth != tree_depth` → reject) and the root is deserialized
    at that layer count, so the depth is bound to the proof and the anchor
    — interior not walked (§3.4). Routed to I13's row; no ruling here.
    **Also corrected in the same doc:** step 1's design rationale still
    listed the retired claim-era "staked" maturity arm (CEN-L12's row
    already records it as never existing in code). The CSR register's
    CEN-I12 row stays failed-closed until re-reviewed at a sha containing
    this reconciliation; that re-review must walk all three read sites and
    rest on the state definition plus B5, not on slice 7's placeholder
    rationale.

---

## 8. Evidence-archaeology payload — disposition of every item

Every pointer in the C1 dispatch's Appendix A, re-verified at the pin and
either folded or rejected with reason. (Line references into `CHANGELOG.md`
re-located per §7.11; all other files are unchanged between the walkers'
sha and the pin.)

| # | Payload item | Verified | Disposition |
| --- | --- | --- | --- |
| 1 | MTP/FTL: DAA §4 :913–914, :1008; §5.5 :1511/:1515; CHANGELOG constant swap | ✅ (swap re-located :14858–14863) | Folded: CEN-C1 evidence; CEN-C2 is the adjudicated off-by-equality row |
| 2 | Block-weight SPLIT: bounds frozen GTWF §10 :803; fossil flag :806–811; 300k consumed ASW :130 + decision log :4686; penalty KAT-port CHANGELOG (re-located :1178); 1.7×/×50 no record | ✅ | Folded: CEN-G6 (`pinned-not-re-derived`), CEN-G6b (fossil flag + FOLLOWUPS), CEN-F14b (`KAT-port` split) |
| 3 | Dynamic fee: P2 :1309 examined-disposition; Fh ruling :4688; 0.95/mask/ref-weight no record | ✅ | Folded: CEN-M3 (`examined-disposition`); Fh adjudicated wallet-side (§7.5) |
| 4 | ≥2 outputs ratified: GTWF :167, :469; DSV K1 :1321 | ✅ | Folded: CEN-I1 (`ratified`) |
| 5 | KI sort order deeply examined: GTWF §12 :871, bug-fix :162–163; K2 :1322 | ✅ | Folded: CEN-I5 (`ratified`) |
| 6 | KI domain/torsion: M8 :1289 examined-disposition; output-point torsion ratified :363/:404–408; CT2 :184 | ✅ | Folded: CEN-H11 (`examined-disposition`; the ratified torsion rulings cover outputs — CEN-H7 — not the KI check) |
| 7 | Coinbase unlock 60 pinned-not-re-derived: GTWF §13 :907; CT2 :248; MERKLE :201 | ✅ | Folded: CEN-F6 (`pinned-not-re-derived`) |
| 8 | unlock_time bans ratified two layers: GTWF :888–891; P1 :1308; decision log :4325–4327 | ✅ | Folded: CEN-H16 + CEN-M5 (`ratified`) |
| 9 | Decomposed amounts examined-and-mooted: GTWF :454; AWPE :973 + §12.3 F-H ("Recommended", no ratified marker) | ✅ | Folded: CEN-F12 notes (combined with the dead-branch adjudication; class stays `none` — a recommendation is not a ratification) |
| 10 | View tags ratified: GTWF :308–309; FA-6 signed; M9/O5 | ✅ (S5 nuance, §7.12) | Folded: CEN-H12/F8 (`ratified`) |
| 11 | tx_extra: bound frozen :791; P3 :1310; canonical-form arbitration deferred to credit-wire lane | ✅ | Folded: CEN-M4 (`examined-disposition`; deferred-not-done note) |
| 12 | Checkpoints SPLIT: compiled-hash shipping decision open DRP :12574–12589; hardcoded checkpoints no record, only RELEASE_CHECKLIST :73; steering tree-facts | ✅ (tree-facts re-verified, §7.8) | Folded: CEN-E3 (`examined-disposition`), CEN-E1 (`none` + tree-facts) |
| 13 | Mempool constants: livetime consumed-as-given DSV :942–943; pool weight cap + relay floor never ratified | ✅ | Folded: CEN-M10, CEN-M3 |
| 14 | Alt-chain/reorg: no examined-decision record (search terms listed); peripheral CT2 :422, ACS :292 (720), RPC quirk RKC :563 | ✅ | Folded: §6.5 + K-family rows |
| 15 | MERKLE_TREE.md misnames its subject | ✅ | Folded: §6.9 (cross-reference only) |
| 16 | Broken pointers: REL §5.5 :494–503 not VIN_PLAN §4; RF-D10 :772 not RF-D1; AWPE §12.12 :2121 not §6.2 | ✅ | Folded: fixed in CEN-H14, CEN-J1/J2, CEN-F19 (§7.10) |
| 17 | Attestation: ratified in full, empty-root slice enforced pre-cutover (ACW :214–223) | ✅ | Folded: CEN-B4 enforcement-status note |
| 18 | PC-D3 load-bearing interim, deletion at cutover (2026-08-26 disposition) | ✅ (:134) | Folded: CEN-J9 note |
| 19 | FCMP ref ages MIN=5/MAX=100: no design-doc pin; Decision 14 = the value event (re-located :26404–26407) + 2026-05 audit trail | ✅ | Folded: CEN-I11 evidence |
| 20 | RandomX seed-epoch spec lives in RANDOMX_V2_RUST.md :393/:790–823, not PLAN or SPEC_ANCHORS | ✅ | Folded: CEN-D3 evidence |

---

## 9. Accounting — every input id resolved

Legend: **merged-into CEN-x** (same rule; sites/notes folded);
**split-into CEN-x, CEN-y** (components landed in different rows);
**dead-surface §5.n** (not a live rule; recorded there);
**rejected-as-nonrule (reason)** (outside the consensus-validation
denominator; routed where stated). `[m]` = the RC row minted a new CEN id.

### 9.1 RC-1…RC-182 (181 issued ids + the unissued RC-156)

Summary of the 161-vs-181 arithmetic: of RC's 181 issued ids, **8 minted
new CEN rows**, **4 resolved to dead-surface records** (RC-32, RC-80,
RC-98, RC-99), **1 is the §4.M axis definition** (RC-151), **1 was
rejected as non-rule** (RC-159), and the remaining **167 merged or split
into existing CEN rows** (RC's finer granularity — e.g. four PQC-structure
rows onto CEN-I16 — accounts for the compression; CEN's deeper frontier
accounts for the CEN-only rows RC never had).

| RC id → disposition | | | |
| --- | --- | --- | --- |
| RC-1 → merged-into CEN-A5 | RC-2 → merged-into CEN-A6 | RC-3 → minted CEN-A7 [m] | RC-4 → merged-into CEN-A1 |
| RC-5 → merged-into CEN-A2 | RC-6 → merged-into CEN-A4 | RC-7 → minted CEN-B6 [m] | RC-8 → merged-into CEN-B1 |
| RC-9 → merged-into CEN-B2 (predicate corrected, §7.3) | RC-10 → merged-into CEN-B1 | RC-11 → merged-into CEN-A3 | RC-12 → merged-into CEN-B4 |
| RC-13 → merged-into CEN-B4 | RC-14 → merged-into CEN-B5 | RC-15 → merged-into CEN-E3 | RC-16 → merged-into CEN-E1 |
| RC-17 → minted CEN-B7 [m] | RC-18 → merged-into CEN-G1 | RC-19 → merged-into CEN-D4 | RC-20 → merged-into CEN-D4 |
| RC-21 → merged-into CEN-D4 | RC-22 → split-into CEN-D2, CEN-D3 | RC-23 → merged-into CEN-D2 | RC-24 → split-into CEN-D1, CEN-D1b |
| RC-25 → merged-into CEN-D3 | RC-26 → merged-into CEN-D5 (dissent recorded) | RC-27 → merged-into CEN-D3 | RC-28 → merged-into CEN-D7 |
| RC-29 → merged-into CEN-C1 | RC-30 → merged-into CEN-C3 | RC-31 → merged-into CEN-C2 (adjudicated) | RC-32 → dead-surface §5.2 |
| RC-33 → merged-into CEN-F1 | RC-34 → merged-into CEN-F1 | RC-35 → merged-into CEN-F2 | RC-36 → merged-into CEN-F3 |
| RC-37 → merged-into CEN-F4 | RC-38 → merged-into CEN-F5 | RC-39 → merged-into CEN-F6 | RC-40 → merged-into CEN-F7 |
| RC-41 → merged-into CEN-F8 | RC-42 → merged-into CEN-F9 | RC-43 → merged-into CEN-F10 | RC-44 → merged-into CEN-F11 |
| RC-45 → merged-into CEN-F12 (adjudicated) | RC-46 → merged-into CEN-F12 | RC-47 → merged-into CEN-F18 | RC-48 → merged-into CEN-F13 |
| RC-49 → merged-into CEN-F16 | RC-50 → merged-into CEN-F17 | RC-51 → merged-into CEN-G12 | RC-52 → merged-into CEN-F19 |
| RC-53 → merged-into CEN-H1 | RC-54 → minted CEN-H23 [m] | RC-55 → merged-into CEN-H8 | RC-56 → merged-into CEN-H19 |
| RC-57 → merged-into CEN-H4 | RC-58 → merged-into CEN-H5 | RC-59 → merged-into CEN-H5 | RC-60 → merged-into CEN-H6 |
| RC-61 → merged-into CEN-H6 | RC-62 → merged-into CEN-H7 | RC-63 → merged-into CEN-H8 | RC-64 → merged-into CEN-H9 |
| RC-65 → merged-into CEN-H10 (dissent recorded) | RC-66 → minted CEN-H24 [m] | RC-67 → merged-into CEN-H11 | RC-68 → merged-into CEN-H2 |
| RC-69 → merged-into CEN-H3 | RC-70 → split-into CEN-H15, CEN-H18, CEN-H19 | RC-71 → merged-into CEN-M2 | RC-72 → merged-into CEN-I1 |
| RC-73 → merged-into CEN-H13 | RC-74 → merged-into CEN-H14 | RC-75 → merged-into CEN-H15 | RC-76 → merged-into CEN-I2 |
| RC-77 → merged-into CEN-H16 | RC-78 → merged-into CEN-H12 | RC-79 → merged-into CEN-H17 | RC-80 → dead-surface §5.2 |
| RC-81 → merged-into CEN-I4 | RC-82 → merged-into CEN-I3 | RC-83 → merged-into CEN-I5 | RC-84 → merged-into CEN-I6 |
| RC-85 → merged-into CEN-I7 | RC-86 → merged-into CEN-I2 | RC-87 → merged-into CEN-I8 | RC-88 → merged-into CEN-I9 |
| RC-89 → merged-into CEN-I10 | RC-90 → merged-into CEN-I11 | RC-91 → merged-into CEN-I11 | RC-92 → merged-into CEN-I13 |
| RC-93 → merged-into CEN-I14 | RC-94 → merged-into CEN-I15 | RC-95 → merged-into CEN-I15 | RC-96 → merged-into CEN-E4 |
| RC-97 → merged-into CEN-H19 | RC-98 → dead-surface §5.1 | RC-99 → dead-surface §5.3 (+ CEN-L1 note) | RC-100 → split-into CEN-I8, CEN-I18 |
| RC-101 → merged-into CEN-I16 | RC-102 → merged-into CEN-I16 | RC-103 → merged-into CEN-I16 | RC-104 → merged-into CEN-I16 |
| RC-105 → merged-into CEN-I17 | RC-106 → merged-into CEN-I18 | RC-107 → merged-into CEN-I17 | RC-108 → merged-into CEN-I18 |
| RC-109 → merged-into CEN-H20 | RC-110 → merged-into CEN-J2 | RC-111 → merged-into CEN-J9 | RC-112 → merged-into CEN-J3 |
| RC-113 → merged-into CEN-G7 | RC-114 → split-into CEN-J4, CEN-J5, CEN-J6, CEN-J7 | RC-115 → split-into CEN-J8, CEN-J9 | RC-116 → merged-into CEN-J10 |
| RC-117 → merged-into CEN-J11 | RC-118 → split-into CEN-J12, CEN-J13 | RC-119 → merged-into CEN-H21 | RC-120 → merged-into CEN-H21 |
| RC-121 → split-into CEN-J14, CEN-J16, CEN-J17, CEN-J18 | RC-122 → merged-into CEN-J13 | RC-123 → merged-into CEN-G10 | RC-124 → merged-into CEN-J19 |
| RC-125 → merged-into CEN-J20 | RC-126 → merged-into CEN-J26 | RC-127 → merged-into CEN-H22 | RC-128 → split-into CEN-J23, CEN-J24, CEN-J25 |
| RC-129 → merged-into CEN-J22 | RC-130 → merged-into CEN-G9 | RC-131 → merged-into CEN-G11 | RC-132 → merged-into CEN-G11 |
| RC-133 → merged-into CEN-G6b | RC-134 → merged-into CEN-K1 (dissent recorded) | RC-135 → merged-into CEN-E2 | RC-136 → merged-into CEN-K6 |
| RC-137 → merged-into CEN-K6 | RC-138 → merged-into CEN-K5 | RC-139 → merged-into CEN-K7 | RC-140 → merged-into CEN-K8 |
| RC-141 → merged-into CEN-K8 | RC-142 → merged-into CEN-B3 | RC-143 → merged-into CEN-L3 | RC-144 → merged-into CEN-L1 (dissent recorded) |
| RC-145 → merged-into CEN-L2 | RC-146 → merged-into CEN-L2 | RC-147 → merged-into CEN-L3 | RC-148 → merged-into CEN-K3 |
| RC-149 → merged-into CEN-L6 (dissent recorded) | RC-150 → merged-into CEN-L1 | RC-151 → the §4.M axis definition (meta-rule, not a row) | RC-152 → merged-into CEN-M3 |
| RC-153 → merged-into CEN-M3 | RC-154 → merged-into CEN-M4 | RC-155 → merged-into CEN-M5 | RC-156 → never issued (RC's own record: draft duplicate of RC-53) |
| RC-157 → split-into CEN-M6, CEN-M7 | RC-158 → merged-into CEN-K10 (flag dissent recorded) | RC-159 → rejected-as-nonrule (relay-privacy class, not tx-validity — RC's own reclassify note; owned by the [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) Q12 lane) | RC-160 → merged-into CEN-M10 |
| RC-161 → merged-into CEN-M2 | RC-162 → merged-into CEN-B1 | RC-163 → merged-into CEN-B3 | RC-164 → merged-into CEN-B3 |
| RC-165 → merged-into CEN-B3 | RC-166 → merged-into CEN-B3 | RC-167 → merged-into CEN-H12 | RC-168 → merged-into CEN-B3 |
| RC-169 → merged-into CEN-F14 | RC-170 → merged-into CEN-F15 | RC-171 → merged-into CEN-F15 | RC-172 → minted CEN-F20 [m] |
| RC-173 → merged-into CEN-L10 | RC-174 → merged-into CEN-L3 | RC-175 → merged-into CEN-L4 | RC-176 → merged-into CEN-L7 |
| RC-177 → merged-into CEN-L8 | RC-178 → merged-into CEN-L9 | RC-179 → merged-into CEN-L7 | RC-180 → minted CEN-L15 [m] |
| RC-181 → merged-into CEN-G6b | RC-182 → minted CEN-F21 [m] | | |

### 9.2 CEN-A1…CEN-M11 (all 161 input ids)

Every CEN id from `CONSENSUS_RULE_CENSUS_3.md` appears in §4 **under the
same id**. A range row below asserts every id in the range carried at its
input bucket and flag (notes/sites possibly enriched by the merge); ids
whose classification changed are excluded from ranges and listed
individually.

| CEN id(s) | Disposition |
| --- | --- |
| `CEN-A1…A6` | carried |
| `CEN-B1…B5` | carried |
| `CEN-C1` | carried |
| **CEN-C2** | **bucket 2 → 4**, class `ratified-premise-refuted` (adjudicated; §7.1) |
| `CEN-C3` | carried |
| **CEN-D1** | carried at bucket 1; **split** — comparison mechanics moved to new CEN-D1b (bucket 4, `KAT-port`) |
| `CEN-D2…D7` | carried |
| `CEN-E1, E2, E4, E5` | carried |
| `CEN-E3` | carried at bucket 4; class formalized `examined-disposition` |
| `CEN-F1…F5` | carried |
| **CEN-F6** | **bucket 2 → 4**, class `pinned-not-re-derived` |
| `CEN-F7…F13` | carried |
| **CEN-F14** | carried at bucket 1; **split** — penalty curve moved to new CEN-F14b (bucket 4, `KAT-port`) |
| `CEN-F15…F19` | carried |
| `CEN-G1…G5` | carried |
| **CEN-G6** | **bucket 2 → 4**, class `pinned-not-re-derived` |
| `CEN-G6b…G13` | carried |
| **CEN-H1** | **bucket 2 → 4**, class `pinned-not-re-derived` |
| `CEN-H2` | carried |
| **CEN-H3** | **bucket 2 → 4**, class `examined-disposition` |
| `CEN-H4` | carried |
| **CEN-H5** | **bucket 4 → 1** (E3 vin-taxonomy evidence located; RC-59's reading) |
| `CEN-H6…H10` | carried |
| **CEN-H11** | **bucket 2 → 4**, class `examined-disposition` |
| `CEN-H12…H22` | carried |
| `CEN-I1…I18` | carried |
| `CEN-J1…J26` | carried |
| `CEN-K1…K7 (incl. K5b)` | carried |
| **CEN-K8** | **bucket 2 → 4**, class `examined-disposition` |
| `CEN-K9, K10` | carried |
| `CEN-L1…L14` | carried |
| `CEN-M1, M2` | carried |
| **CEN-M3** | **bucket 2 → 4**, class `examined-disposition` |
| **CEN-M4** | **bucket 2 → 4**, class `examined-disposition` |
| `CEN-M5…M11` | carried |
| *(new in the merge)* | CEN-A7, B6, B7, F20, F21, H23, H24, L15 (minted); CEN-D1b, F14b (split) |

Bucket-2 reconciliation total: CEN's 23 → 14 merged (nine demotions above);
RC's 6 bucket-2 rows all land at merged bucket 2 or carry their class
(RC-24 → D1b `KAT-port`; RC-31 → C2 `ratified-premise-refuted`; RC-56 →
H19 `none`; RC-72 → I1 `ratified`; RC-83 → I5 `ratified`; RC-151 → axis
definition). RC's 16 bucket-3 rows: 2 survive at bucket 3 (H24, L15), the
rest resolve per §1's bucket-3 posture.

### 9.3 Survey A (U-items, L-items, buckets S/R/D, O-items)

| Item | Disposition |
| --- | --- |
| U-1 hardfork machinery | merged-into CEN-B1/B2/B3 + §5.5 (dead dispatch); the collapse-vs-redesign question is §10 R4's, with the V4-activation question attached (rules 75/21) |
| U-2 `unlock_time` residue / "two spendability mechanisms" | resolved as finding §6.2: the curve tree is the sole enforcer (CEN-L12); the inherited per-output unlock check survives only on dead surfaces (§5.1/§5.2); rows CEN-H16, M5, L12, F6. §10 R5 |
| U-3 alt-chain / reorg | merged-into the CEN-K family + finding §6.5. §10 R1 |
| U-4 tx pool relay decisions | validity/policy half merged-into the CEN-M family (§10 R7); the pool-vs-Dandelion++ relay-*timing* question is relay-privacy material for the [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) lane, recorded in R7's stake statement |
| U-5 `rpc_credits_per_hash` in the handshake | rejected-as-nonrule (p2p wire field; no acceptance-path check) — routed to the P2P protocol redesign lane with the L-items; Survey A's free-deletion-pre-genesis observation carried there |
| U-6 `NOTIFY_NEW_BLOCK` alongside fluffy | rejected-as-nonrule (block propagation above the acceptance entry points) — routed to the P2P protocol redesign lane |
| U-7 output histogram / distribution RPC | rejected-as-nonrule (RPC read surface; no acceptance-path check) — rule-60 deletion candidate; its dead `HF_VERSION_DYNAMIC_FEE` height lookup is covered by §5.5 |
| U-8 timestamp validation | merged-into CEN-C1/C2/C3; the algorithm-vs-spec question U-8 asked is answered and sharpened by the C2 adjudication. §10 R3 |
| U-9 `miner.cpp` audit | rejected-as-nonrule for this census (block *production*, not validation). The open audit question — the miner-chosen coinbase-revealed challenge origin, and whether an in-daemon miner should exist on a node holding staking keys — is recorded here as adjacent-surface input; it has no owner yet and any future round touching `miner.cpp` starts from Survey A §5 U-9 |
| L-1…L-6 (Levin wire) | out of the consensus census: requirements input to the **P2P protocol redesign lane** (ruled 2026-08-31); `CONSENSUS_RULE_CENSUS_1.md`'s banner carries the forward pointer |
| Bucket S list | maps onto merged bucket-1 families (FCMP++, PQC, RandomX v2, LWMA-1, archival, deferred insertion, fee-scaling KATs) — closed, not reopened (O-4) |
| Bucket R list | 2021 fee scaling → CEN-M3 (`examined-disposition`; the claimed "A3 fee round" record was not locatable, §7.6); weight penalty → CEN-F14/F14b; LMDB `pop_block` reversal atomicity (Phase 4 audit) → evidence context for CEN-B5/K5/L-family pop-side belts |
| Bucket D list | rule 60's named-deletion list; discharge state recorded in Survey A §4 (partially discharged) — §5/§10 R5 carry the residue |
| O-1…O-4 | folded into §6.10–§6.12 |

---

## 10. The C2 design-round queue

Every bucket-3/4 row **as of C1 close** (70 = 68 + 2 — the queue
denominator is frozen at dispatch; rulings are tracked per batch row and in
the per-row bucket/class columns, so this table is a dispatch record, not a
live bucket count, and is not renumbered as rows leave bucket 4). Grouped
into dispatchable subsystem batches, one stake statement per batch: **what
becomes permanent at genesis if the batch goes unruled.** Proposed order:
R3 → R1 → R2 → R4 → R5 → R8 → R6 → R7 → R9 — the early R3 slot is the
steering-flagged MTP ruling; after it, batches run in descending
(permanence-risk × interconnection) order. This queue is what makes C2
dispatchable the day C1 lands; batch membership below is exhaustive over
the bucket-3/4 rows at C1 close (counts sum to 70).

| Batch | Rows (count) | Stake at genesis if unruled |
| --- | --- | --- |
| **R3 — Timestamps** — **RULED 2026-09-01** ([`CONSENSUS_C2_R3_TIMESTAMPS.md`](../completed/CONSENSUS_C2_R3_TIMESTAMPS.md): Q1 strict `>` + newest-11 alt window + `median+1` template floor, Q2 genesis-padding replaces the carve-out, Q3 FTL at alt admission; CEN-C2/C3 → bucket 2, §7.15) | CEN-C2, C3 (2) + CEN-C1's alt-FTL placement note | The MTP boundary shipped three-way split (strict ratified spec / non-strict live C++ / strict unwired Rust predicate) — a consensus-forking discrepancy the rewrite would have had to *choose* silently; LWMA-1's security assumptions rest on timestamp validation. Was flagged for an early ruling + a boundary test (adjudicated ground already in CEN-C2) |
| **R1 — Reorg / alt-chain + checkpoints + topology** — **RUNNING** ([`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md); three decision-grouped sub-rounds 2+9+9; **R1a RULED 2026-09-02**: CEN-E3/E4 removed-and-executed, CEN-G8 retired, rule 71 minted with its grep gate; census-wide line re-anchor deferred to R1c close, owner: this round) | CEN-K1–K10, E1–E5, A1, A2, A4, D5, D6 (20) | The fork-choice rule (strictly-greater + checkpoint-forced), the prevalidate-only alt-admission subset (§3.5), checkpoint trust surfaces (incl. the PoW/FCMP-skipping compiled-hash path), and reorg semantics across staking-epoch boundaries — none examined on record (§6.5) — freeze as the permanent reorg contract of a chain whose archival state is epoch-scoped |
| **R2 — Block-weight / reward-zone / fee constants** — **DEFERRED (Rick, 2026-09-03).** New terminal-emission findings from the fee-ladder round jump this queue. R2 resumes when **both**: (a) the terminal emission ruling **FL-R12′** is signed in `FEE_LADDER_DERIVATION.md` §8 (that doc lands with the fee-ladder lane; not yet on dev), and (b) `projected_already_generated` carries a red test at the exhaustion boundary. Conjunct (b) is **discharged** — `terminal_reward_legs_agree`, `#[ignore]`d, observed red (600000000 vs 599999999 at the first diverging block). Conjunct (a) is open. §12 GAP-8 records the composition finding underneath the deferral. | CEN-G6, G6b, F14b, H1, H3, M3, M4, M10 (8) | The 300 000 reward zone (an explicitly punted "fossil flag" arbitration), the 1.7× clamps, ×50 surge, the ArticMine penalty curve, the 1 MB tx cap, and every fee-formula constant fossilize as Shekyl economics without ever having been derived for Shekyl |
| **R4 — Header identity + hardfork collapse** | CEN-B2, B3, B6, B7, A5, A6, A7, H23 (8) | The wire-identity binding (no explicit merkle field — B6) and the inert voting machinery freeze; **the V4 lattice-only activation question must be answered by design, per rules 75/21 — recorded here, deliberately not answered**: collapse-vs-redesign of the hardfork subsystem is exactly that question's mechanism half |
| **R5 — Coinbase + tx structural residue (incl. bucket-3 executions)** | CEN-F1, F5, F6, F7, F12, H4, H8, H9, H10, G1, G2, G3, G5 + H24, L15 (15) | The coinbase contract (pinned-not-re-derived unlock window 60, the load-bearing-dead decomposed arm a naive Rust port would implement as live), the structural belts, and the rule-60 deletions (H24, L15) become permanent — dead branches are the cheapest deletion pre-genesis and a port hazard forever after |
| **R8 — Storage-layer enforcement placement** | CEN-L1–L6, L13, L14 (8) | "Validation completed by a side effect of the write path" (KI uniqueness as an LMDB exception, verbatim-hash storage, verify-side-only uniqueness) becomes the rewrite's implicit spec — the rewrite must place each rule deliberately or inherit the accident |
| **R6 — Inherited crypto verifiers on the acceptance path** | CEN-H11, H19, D1b (3) | The KI-domain check (submit-path-examined only, coupled to the open FCMP y-normalization question), the inherited C++ BP+ verifier (inventory disposition still *pending*), and the KAT-sealed PoW comparison ship as cryptographic consensus surfaces whose right-for-Shekyl was never ruled — a seal is not a ratification |
| **R7 — Mempool admission semantics** | CEN-M1, M2, M6, M7, M11 (5) | Pool idempotency, NIC caching, and relay-side spend pre-checks freeze as the de-facto admission contract; U-4's open question rides here — whether the pool makes any relay-timing decision independent of the Dandelion++ layer (a privacy-leak channel no relay round examined, because the rounds examined the relay layer and not the pool) |
| **R9 — Test levers in production consensus paths** | CEN-D7 (1) + the §6.8 carve-out finding (I2/B5/D3-env notes) | Regtest seams compiled into consensus functions fossilize; the rewrite needs a designed test seam, not inherited `FAKECHAIN` branches |

The 87 bucket-1 and 14 bucket-2 rows are **closed by this census** (Survey
A O-4): the rewrite consumes their specs and ratification records directly;
reopening them requires new evidence, not a new walk.

---

## 11. Re-running and diffing this census

1. Re-pin `git rev-parse HEAD`; diff the tree against
   `ab3cc98e6eb73db2b309730ccc9853ba4ea95e7d`.
2. Re-walk the §3.3 frontier from the four entry points. New callee that
   can reject ⇒ new row (next free id in its family). Deleted callee ⇒
   strike the row with a disposition note. Line shifts without behavioral
   change are a census update, not a new rule.
3. Re-run the §3 count commands; §3/§3.1 must be updated in the same edit
   as any row change (the counts are load-bearing).
4. Inverse spot-check the six §3.2 subjects. Absence is evidence the walk
   broke, not that the rule went away.
5. The archived input documents are frozen: a correction discovered later
   lands **here**, with a §7-style decision-log entry, never in the
   archived walks.

**Out of scope (restated from the inputs and the C1 dispatch):** no code
changes, no FFI work, no differential tests, no rulings on whether any
bucket-4 rule is right for Shekyl. The project's fix-don't-defer discipline
was deliberately suspended for the census passes: the row is the work unit;
defects noticed are FOLLOWUPS one-liners, not fixes.

---

## 12. Negative space — the C2-R0 GAP register

This register is the census's complement: rows for consensus rules that
**ought to be considered and have no site** — either the rule is absent from
the tree, or the defect lives in a relation between sites that are each
individually correct. A site-anchored census structurally cannot carry
either kind: every §4 row is born from a `file:line`, so a missing rule has
nowhere to appear. The C2-R0 round (dispatched 2026-09-03) exists because of
that blindness. GAP rows sit **outside the §3 denominator** — the
denominator is site-anchored by construction and its sum checks must not
absorb rows whose defining property is having no site. Two sums are
therefore stated separately: §3's **171** site-anchored rows, and this
register's **8** GAP rows. Neither counts the other.

**Grounding pin:** dev `920a7d788` (2026-09-03, the PR #606 merge — after
the C2-R1b landing). **Provenance rule:** every GAP row's first column
cites its phase-1 candidate id (C1–C13 of
[`C2_R0_PHASE1_CANDIDATES.md`](C2_R0_PHASE1_CANDIDATES.md), landed with
this register) or names itself a steering-routed carry — two id spaces meet
at this handoff, and a row without the mapping would strand its evidence.

**The worked example — why a row-per-site instrument cannot see this
class.** Two supply clamps ship, each individually correct, each accurately
described at its own site, and the defect exists only in the relation
between them. `src/shekyl/shekyl_ffi.h:333–335` documents them as
complementary halves of one mechanism:

> "Cap a block reward at the supply headroom still unminted. The
> emission-side **twin** of `shekyl_advance_already_generated`: that one
> stops the running total at the cap, this one stops a single block from
> exceeding what remains."

while the comment above the advance call (`blockchain.cpp:6350–6353` at the
pin) states the opposite terminal policy as a consequence:

> "the number of coins will eventually exceed MONEY_SUPPLY … cap
> already_generated_coins at MONEY_SUPPLY … MONEY_SUPPLY yields a subsidy
> of 0 under the base formula and therefore the minimum subsidy >0 in the
> tail state."

The header's "twin" asserts one mechanism distinguished only by scope; the
tail comment encodes emission-continues-forever; the cap function pays
**zero** at exhaustion. Each comment is true about its own function and
silent about the other's policy — a reader holding both in mind could not
have written either sentence, so **the tree's own prose is the evidence
that the composition was never examined** (the code alone could be an
accident; the documentation proves nobody looked). "Which side did the code
take" was malformed: it took both. GAP-8 carries it.

**External-evidence spot-check (run before any external claim entered a
row, 2026-09-03).** The load-bearing quantitative claims trace to arXiv
2512.01437 ("Inside Qubic's Selfish Mining Campaign on Monero"),
re-fetched at the primary source: 23.38% average share / 28.33% during
withholding periods, ten periods (P1–P10), 3,239 accepted blocks, the
3.22-percentage-point target-rate shortfall, and the tie-break race-win
rates 0.49 at α=0.35 (P1) and 0.60 at α=0.34 (P3) all verify verbatim.
One decompression the rows carry: the **+461.8 block-equivalents**
difficulty-adjustment spillover and the **−460.0 block-equivalents (4.0%)**
aggregate deficit are *separate ledger lines* of near-equal magnitude —
phase 1's "after crediting … still 460 below" chained them causally; they
must not be read as one number netted. The 51% claim verifies as scoped:
short intervals briefly exceeded 50%, daily/weekly **aggregates never
reached 51%**, and no stable majority was held. The Monero 18-block reorg
(height 3,499,659, 118 transactions, ~36 minutes, 2025-09-14/15,
attributed to Qubic's withheld chain) confirms across multiple independent
outlets. Phase 1's two marked non-primary claims (ETC Jan-2019 *secondary*;
Horizen ~10× *self-reported*) keep their markings in any row that touches
them.

### 12.1 GAP rows

| Id | The absent rule (recorded as a QUESTION) | Source | Grounding at `920a7d788` | Disposition / owner |
| --- | --- | --- | --- | --- |
| GAP-1 | Maximum reorganisation depth (finality bound): should any depth bound exist, and in what form? | C1 | ABSENT — `fork_choice` (`rust/shekyl-difficulty/src/fork_choice.rs:46–59`) is checkpoint-match ∥ strictly-greater, nothing else; `ARCHIVAL_REORG_DEPTH_BLOCKS` (720) has zero consensus-side hits (engine scan ceiling `pscan/start.rs:93` + economics-sim reach only); the R1b prune watermark is a node-local storage floor, explicitly not a protocol bound ([`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b) | **R1c input — question only, per the round's standing hand-off; no disposition here.** R1c inherits as *evidence, not conclusions*: the corpus (Vertcoin 307/603-deep; BTG's self-financing ≈0.2 BTC/reorg; ETC 3,693–7,000+ blocks, $5.6M; Monero 18-block 2025-09), the retrofit record (BCH-ABC 10-block rule; ETC MESS shipped → disclosed-vulnerable → deactivated by ECIP-1110), the real-time attack-vs-accident misclassification dilemma (ETC 2020-08-01's first read was wrong, in the reassuring direction), the permanent-split trade (a depth limit converts a reversible attack into an irreversible one), the no-principled-`R` problem, and the sunset-criterion requirement |
| GAP-2 | Late-block penalty / publish-or-perish weighting in fork choice: should receive-time influence the verdict? | C2 | ABSENT — the fork-choice signature carries two cumulative difficulties and a checkpoint flag; no timing input exists anywhere in the verdict path | Own design-round question (R1c-adjacent). Measured exploitation of first-seen tie-breaking is real (spot-checked race-win rates above); the counter-record is real too (MESS's subjectivity → partition vulnerability; RandomX verify cost disqualifies share-sampling designs, research-lab#144). Phase-1 confidence medium — not pre-empted here |
| GAP-3 | Stake-quorum block finality (a ChainLocks-shaped rule), given staking already exists | C6 | ABSENT — the staking system exists; nothing consumes it as a finality quorum | **Rule-21 REJECTED** (steering ruling, 2026-09-03): incompatible with the privacy constitution as currently constructible. Two OR'd reopeners: (a) a standardized **signer-hiding** PQ threshold signature, or (b) a design where quorum participation is statistically indistinguishable from sparse challenge traffic (flagged *may be impossible in principle*). The reopening event **convenes a round, never clears a build** — a signer-hiding threshold signature fixes tier 1 only, and tier 2 survives it intact: first-relay correlation against a *scheduled* per-height emission, priced strictly easier than the sparse unscheduled target D++ already spends embargo tables and fragmentation windows defending. [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) "Threshold signatures: one missing primitive, two named customers" agrees in its own words — the event "reopens both customers at once". Carries the tier-1 caveat verbatim: a fat k-of-n certificate is an **attested, gap-free, permanent** persona-linkage oracle — absences are recorded, not merely unobserved |
| GAP-4 | Anti-DoS sync: minimum cumulative work and bounded header acceptance (not checkpoints) | C7 | ABSENT — `minimum_chain_work`/`min_chain_work`: 0 hits in `src/`; no `assumevalid` analogue; `BLOCKS_SYNCHRONIZING_MAX_COUNT` (`cryptonote_config.h:95`) is a batch size, not a work gate; R1a deleted the compiled-hash fast path, removing the checkpoint-shaped trust surface without replacing its anti-DoS role | Design-round question; couples to R1c's cheap-deep-fork seeds (`build_alt_chain` re-walks the entire alt ancestry per admission — [`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §5) |
| GAP-5 | Cross-window constraint: every maturity/bond/lock window must state its relation to the finality bound | C8 | Structurally ABSENT — no finality bound exists (GAP-1), so no coupling constraint can; the windows themselves are site-anchored (CEN-F6's 60, CEN-L12's 10, the staking/unbond windows) with no cross-window row anywhere | Conditional on GAP-1's resolution: whatever R1c rules — a bound, or explicitly none — the windows inherit a *stated* relation to it (the Bittrex-600-cleared-by-603 case is the canonical cost of leaving the relation unstated) |
| GAP-6 | Launch-phase emission ramp (slow start) | C10 | ABSENT — emission runs full-rate from the first block (`emission_speed_factor_per_minute: 22`, `config/economics_params.json:5`, standard right-shift curve); a genesis *allocation* exists (`config/genesis_recipients.*.json`) but no block-subsidy ramp | Economics-lane design question. The terminal end of the same curve is R2-deferred territory (FL-R12′, §10); this row is the LAUNCH end and must not ride that deferral silently — if the lanes merge it, the merge is a decision, not a default |
| GAP-7 | A bounded worst-case block **verification cost** — a cost model on the provisioning floor, not only size caps | C13 | PARTIAL — the caps exist as R2 rows (CEN-H1's 1 MB, CEN-H3, CEN-G6/G6b) but nothing binds weight to verification time on the rule-76 floor (Pi 4); the RandomX constraint is already on record (research-lab#144: share-sampling designs disqualified — ~1.5 s verify for 100 shares) and applies to Shekyl identically | R2 input, rides the R2 deferral (§10): when R2 resumes, the caps' derivation must include the verification-cost leg, not only the economics |
| GAP-8 | The two supply clamps encode **opposite terminal emission policies** — tail-forever vs pays-zero-at-exhaustion | Steering-routed carry (found in Rick's fee-ladder-round review, 2026-09-03) | Grounded at the pin: advance = `blockchain.cpp:6360` (main) / `:2233` (alt), saturating with the tail-forever rationale in its comment; cap = `cryptonote_basic_impl.cpp:168`, zero headroom at exhaustion; `shekyl_ffi.h:333–335` names them "twins" — both prose quotes above, the worked example | **Resolution IS FL-R12′** (§10 R2 deferral, conjunct (a)) — this row records the question; the ruling lands in the fee-ladder lane and R2 consumes it. This row must not propose its own answer |

### 12.2 Present-already results (a result, not a null)

A candidate that turns out already considered is *recorded*, with the
pointer — a later reader asking "did anyone consider X" needs "yes, and
here is where," never a silence that reads as "nobody looked."

| Candidate | Verdict | Where |
| --- | --- | --- |
| C3 (timestamp discipline) | present-and-ruled | R3 ([`CONSENSUS_C2_R3_TIMESTAMPS.md`](../completed/CONSENSUS_C2_R3_TIMESTAMPS.md)): strict MTP, newest-11 window, FTL 540 s co-tuned with the DAA and static-asserted (`shekyl-difficulty/src/consts.rs:79–83`); bounded past-drift = the MTP window itself. Per-block monotonicity is deliberately absent; the negative-solvetime clamp is the compensator (phase-1-verified as surviving the port) |
| C4 (time-locks vs MTP) | present-and-examined | The `unlock_time` triple-divergence is already census-carried: CEN-H16 (timestamp unlocks **consensus-rejected**), CEN-L12 (maturity = deferred tree insertion; `unlock_time` inert), CEN-M5 (relay ban, `kept_by_block` exempt) + the §6 finding; `is_tx_spendtime_unlocked` is §5-recorded as RPC-serving. The candidate's demanded property holds by construction |
| C5 (local clock, no peer time) | present-by-absence | No peer-time mechanism exists: all 9 `adjusted_time` hits enumerated at the pin — chain-median projection (`blockchain.cpp:5493`) + RPC surfacing; no NTP, no peer delta. A reintroduction-guard is a rule-21 reopening criterion, not a gap |
| C9 (no hashrate-vote activation) | present-unruled, owned | §10's R4 batch IS this question: the inert voting machinery (CEN-A5/A6/A7, B2/B3/B6/B7, H23) and the V4 activation question, recorded-not-answered by design |
| C11 (genesis bootstrapping) | two arms ruled, one routed | Difficulty: the LWMA §5.3 genesis short-circuit (`lwma1.rs:67–70`). Timestamps: R3's genesis-padding ruling. Weight-median bootstrap: R2-owned (CEN-G6/G6b), rides the R2 deferral |
| C12 (work-based fork choice + explicit tie-break) | present-and-ruled | R1b Q1a ([`CONSENSUS_C2_R1_REORG.md`](CONSENSUS_C2_R1_REORG.md) §4b): cumulative difficulty only — heights are never compared at the ruled site; equality-keeps-incumbent is the explicit deterministic tie-break; the discard asymmetry is the flip-flop terminator. The measured tie-break-exploitation numbers (GAP-2's evidence) are recorded as R1c wargame input |

### 12.3 Completion claim

15 dispositions = the 13 phase-1 candidates (**7** GAP rows: C1, C2, C6,
C7, C8, C10, C13 → GAP-1…7; **6** present-already records: C3, C4, C5, C9,
C11, C12) + the 2 steering-routed carries (**1** GAP row: GAP-8; **1**
queue edit: the §10 R2 deferral). Register total: **8** GAP rows. The §3
denominator is untouched (171; buckets 86/25/5/55, re-derived from the row
column at the pin). A GAP row leaves this register only by a dated
disposition note — a design-round ruling, a rejected-with-reopening-criteria
record (rule 21), or promotion to a site-anchored row when a rule lands.
