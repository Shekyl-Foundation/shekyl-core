# FOLLOWUPS entries that are incomplete as written

Register of `docs/FOLLOWUPS.md` entries whose text stops before it states
what the work is. It **lists; it does not rewrite** — no prose is authored into
another family's entry, no blocker is guessed, no disposition is assigned.

## Why this is not a typo list

`23-disposition-visibility.mdc` fixes four dispositions by their grep surface.
DEFERRED requires exactly one FOLLOWUPS row **naming an external blocker**. An
entry that stops mid-sentence cannot name one, so these are not deferrals at
all: they are **undisposed items sitting on the surface an agent greps to find
deferred work**. That is the residue the three dispositions exist to prevent,
and it is why the register exists.

Each row therefore fails the same way, and the register does not pretend to
more precision than that: **the statement of the work is incomplete, so no
blocker is nameable and no disposition can be evaluated.** Which disposition
each item *should* get is its owner's decision, not this document's.

No *falsifier* column is offered, and its absence is deliberate.
`22-no-lazy-deferral.mdc` requires a blocked entry to name the check that would
falsify it — but an entry that never finishes stating the work cannot state a
blocker, so it cannot state a falsifier either, and the column would read "no"
on every row. It would record the consequence and hide the cause. Falsifiers
become answerable per row only once the entry says what the work is, which is
its owner's edit, not this register's.

## Measurements

Against `docs/FOLLOWUPS.md` as merged with `dev` at 804a1131d. Line numbers are
re-anchored to that tree; the counts below are the population this branch
repaired, which is what the register is a record of:

- 350 entries total (`^- \*\*`); **198** had unclosed bold, now closed.
- **101 are incomplete as written** and are listed below.
- Nothing was truncated: across all 1,167 revisions of the file, 195 of 196
  were born at their current length; the one exception gained five characters
  in a version itself unclosed and itself mid-sentence. Recovery is **zero**.
  There is no lost text to restore, here or anywhere in the file.

### Error direction, stated

Section 1 (70 rows) is mechanical: the entry ends on a function word, a
dangling possessive, trailing punctuation, or an unbalanced code span or
bracket. That test **under-detects** — a sentence cut on a content word reads
as complete — so section 1 is a floor.

Section 2 (39 rows) is the boundary set the mechanical test could not
decide, read by hand and recorded per row so the judgement is auditable rather
than folded into a number. 31 were judged incomplete, 8 complete. I would not
defend the total to better than **±10**.

A third shape is deliberately absent: 70 entries end in a documentation
link, so their text runs to a citation and stops. Those read as complete titles
and are **not** listed as incomplete.

Markdown links inside quoted entry text are rendered inert: the quotes are
data, their relative paths were authored for `docs/` and would not resolve
from this directory, and a register is a listing rather than a navigation
surface. The **Owning doc** column carries the path where the entry has one.

## Section 1 — incomplete, detected mechanically

| Line | Target | Owning doc | Entry as it stands |
| ---: | --- | --- | --- |
| 92 | pre-genesis | *undetermined* | TJ-7 (HIGH, sweep input) — sybil-per-shard has NO uniqueness constraint, |
| 95 | pre-genesis | *undetermined* | TJ-8 (briefing constraint on the Round-2 re-pin) — do NOT credit the |
| 101 | pre-genesis | *undetermined* | TJ price premise — NOT codeable, tracked here with its falsifiers as |
| 104 | pre-genesis | *undetermined* | Superseded-section cross-reference sweep (docs hygiene, split out by the |
| 107 | pre-genesis | *undetermined* | Live-pin index, independent of doc status (process-structural — added |
| 128 | pre-genesis | *undetermined* | Round-2 stressnet re-pin of the failure-window `m`/`n` — must be JOINT with |
| 148 | pre-genesis | *undetermined* | GF-7 `stake_in` change-co-presence residual — shipped with a warning, |
| 154 | pre-genesis | *undetermined* | Wallet thin-market entry disclosure — the §13.2 re-disposition's |
| 172 | pre-genesis | `design/WINDOWS_WALLET_SUPPORT.md` | Rust wallet stack: no Windows support (blocks Windows wallet `WINDOWS_WALLET_SUPPORT.md` |
| 181 | pre-genesis | *undetermined* | Phase 4c: no way to abandon an unconfirmed submitted transaction, so a |
| 190 | pre-genesis | *undetermined* | GF4b-2 genesis gate — bond-post funding-input-count leak; `stake_in` |
| 226 | pre-genesis | *undetermined* | Repo-wide `RingCT`/`rct`/`RCT` → `CT` semantic sweep — a Shekyl tx is simply a |
| 229 | pre-genesis | `./completed/CT3_SYNC.md` | Store-backed / pruned-tree path assembly (CT-3 pre-flight F5, `docs/completed/CT3_SYNC.md` |
| 232 | pre-genesis | *undetermined* | C++ path RPC computes a crypto contract (`hash_to_p3`) inline — |
| 238 | pre-genesis | `./completed/CT3_SYNC.md` | `get_curve_tree_leaves` daemon endpoint + KAT (CT-3 R1-Q1 deferral `docs/completed/CT3_SYNC.md` |
| 241 | pre-genesis | *undetermined* | Rollback-adjacent frozen-`R_k` recheck on plain resume (CT-3c C1 |
| 244 | pre-genesis | *undetermined* | Full all-segment frozen-`R_k` recheck (CT-3c bounded-check deferral, |
| 247 | pre-genesis | *undetermined* | Refresh-over-spend reorg: optimistic-spend `spent_height` invariant + |
| 250 | pre-genesis | *undetermined* | `AlreadyInChain` submit verdict: distinct lock-lifecycle disposition — |
| 256 | pre-genesis | *undetermined* | Submit-error reservation-id placeholder: split submitter error from |
| 262 | pre-genesis | `./completed/CT2_ROUND1_CLOSEOUT.md` | CT-2 Tier B reconstruct-root KATs (staked / non-coinbase maturity `docs/completed/CT2_ROUND1_CLOSEOUT.md` |
| 265 | pre-genesis | `completed/DEPTH3_CURVE_TREE_CUTOVER.md` | CT-5 real-tree FCMP++ verify — deeper-tree + pin validation (depth-2 case `docs/completed/DEPTH3_CURVE_TREE_CUTOVER.md` |
| 268 | pre-genesis | `./completed/CT5C_ASSEMBLER_CUTOVER.md` | Output-class numbering-equivalence re-verification (CT-5c X3 standing `docs/completed/CT5C_ASSEMBLER_CUTOVER.md` |
| 280 | pre-genesis | *undetermined* | CT-5d re-confirm UX: handle accessor + `(fee, change)` delta on |
| 283 | pre-genesis | *undetermined* | CT-5d: retire the vestigial `SnapshotId` / `SnapshotInvalidated` submit path, |
| 289 | pre-genesis | `./design/CURVE_TREE_CLIENT.md` | Wallet-local `O.x → position` match index (`CurveTreeClient` §4.3 scan `docs/design/CURVE_TREE_CLIENT.md` |
| 295 | pre-genesis | `./design/CURVE_TREE_CLIENT.md` | Anonymized (Tor/I2P) routing for non-forward segment fetch (CT Round 0 `docs/design/CURVE_TREE_CLIENT.md` |
| 298 | pre-genesis | *undetermined* | Single-dispatcher nm gate: extend beyond `shekyld` (2026-06-11 |
| 307 | pre-genesis | *undetermined* | Foundation treasury diversification — floor capacity must not be |
| 316 | pre-genesis | *undetermined* | Wallet bond-funding/standoff call site (tracks the `shekyl-standoff` |
| 319 | pre-genesis | *undetermined* | `shekyl-stats` `Z_ALPHA_1E6` provenance vs. the `enc_label` test's |
| 334 | pre-genesis | `design/ARCHIVAL_BOND_CONSTRUCTION.md` | Wallet-side archival bond-post construction (design + JoinMarket, PR 0-2a `docs/design/ARCHIVAL_BOND_CONSTRUCTION.md` |
| 337 | pre-genesis | `design/ARCHIVAL_BOND_SP_R0_PLAN.md` | StakeEngine Model D wiring — deferred work + rule-21 reopens (PR 2c-2a, `ARCHIVAL_BOND_SP_R0_PLAN.md` |
| 340 | pre-genesis | *undetermined* | Archival bond request path — deferred items (PR 2c-2b, landed inert |
| 346 | pre-genesis | *undetermined* | USER_GUIDE realignment to the Rust CLI surface (2026-06-10 doc |
| 349 | pre-genesis | `./V3_ENGINE_TRAIT_BOUNDARIES.md` | Stage 1 trait-extraction chain — closeout audit (2026-05-29, `V3_ENGINE_TRAIT_BOUNDARIES.md` |
| 361 | pre-genesis | *undetermined* | Stage 1 PR 3 engine-property test re-location (trigger: |
| 367 | pre-genesis | *undetermined* | `shekyl-fcmp`: resolve `useless_conversion` clippy warnings in |
| 370 | pre-genesis | *undetermined* | Full migration of remaining `SHEKYL_*` FFI constants to the |
| 373 | pre-genesis | *undetermined* | `wallet_storage`: cover loaded-wallet save-as branches in |
| 388 | pre-genesis | `https://github.com/Shekyl-Foundation/shekyl-core/pull/112` | Subaddress mechanism under PQC — dedicated design round (2026-05-31, #112 |
| 397 | pre-genesis | *undetermined* | `tx_extra` `0x02` Nonce: shed from the genesis grammar — FA-10 is |
| 403 | pre-genesis | `design/PHASE_2B_FSM_RETOOL.md` | Phase 2b planning session — stake state-machine shape (gate for `design/PHASE_2B_FSM_RETOOL.md` |
| 412 | pre-genesis | *undetermined* | JSON-RPC large-amount precision — string-amount serde at the RPC edge (spawned |
| 421 | pre-genesis | *undetermined* | RPC boundary refinements — idle eviction, `engine_lock`, |
| 424 | pre-genesis | *undetermined* | `Hybrid*` secret types: `Vec<u8>` for fixed-size scalars — |
| 502 | pre-genesis | `./design/RANDOMX_V2_RUST.md` | RandomX v2 — Guix reproducible-build obligation pickup (trigger: `docs/design/RANDOMX_V2_RUST.md` |
| 544 | pre-genesis | *undetermined* | Term hygiene: "rotation" is a §11.8 defect on a noun — rename to |
| 601 | pre-genesis | *undetermined* | Retire the iai-callgrind→gungraun bench-flake bisect harness (spawned |
| 631 | pre-genesis | *undetermined* | Relay: `on_relay_tx` and a missed submit nudge re-decide the zone after |
| 634 | pre-genesis | *undetermined* | Wallet: stop holding a relay constant — ask the daemon whether a |
| 643 | pre-genesis | *undetermined* | Relay: the `F'` region and §15's launch condition are one condition, and |
| 655 | pre-genesis | *undetermined* | Relay: populate the 48-cell Pi verification surface, then consume it |
| 793 | pre-genesis | *undetermined* | MSVC / Windows build-debt cluster (migrated from |
| 796 | pre-genesis | *undetermined* | P-drain mechanism re-walk — CryptoNote holdover audit (rule 16; method note 5: |
| 799 | pre-genesis | *undetermined* | `P`-lane fee uniformity — implementation rider (ratified 2026-07-19, |
| 817 | pre-genesis | *undetermined* | 2d-2 SP-T0 — DQ-T0.4 circuit-isolation measurement has no CI binary source (BLOCKED, not |
| 823 | pre-genesis | *undetermined* | M1 reward-gate C++ test-support surface — fold the corruption-injection seam off the |
| 826 | pre-genesis | `design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` | Segment-freeze pipeline — design round required (opened by `ARCHIVAL_REWARD_GATE_M1.md` `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` |
| 829 | pre-genesis | *undetermined* | M1 reward gate — pre-flight process BREACH (PF-1, recorded 2026-07-06; a breach, |
| 832 | pre-genesis | `design/ARCHIVAL_BOND_2C_GF7_HOOKS.md` | 2d-2 SP-T4a — GF-7 principal-timeline timing correlation is a GENESIS GATE (measure `ARCHIVAL_BOND_2C_GF7_HOOKS.md` |
| 835 | pre-genesis | *undetermined* | Wallet UX: thin-cover exposure disclosure at bond/claim time (registered 2026-07-19, |
| 871 | pre-genesis | *undetermined* | Stage 5 — `ArchivalEngine` native actor build (simulation- |
| 895 | pre-genesis | *undetermined* | Transport selection for the staker-archival path (gate 6 / |
| 898 | pre-genesis | *undetermined* | Soundness pass step 0: pin retrieval SLA per class (gate 4–6; |
| 904 | pre-genesis | *undetermined* | Archiver seeding-path transport relaxation (gate 6 / firewall; |
| 910 | pre-genesis | *undetermined* | L15 diversity under location-hiding (gate 4–6 / architecture; |
| 913 | pre-genesis | *undetermined* | Permanent fee-era backstop must be a trustless terminal subsidy, |
| 922 | pre-genesis | *undetermined* | Bootstrap APR overshoot is a purse-efficiency note, not a |
| 925 | pre-genesis | *undetermined* | Vanguard eligibility flag set is a provisional pin, unseated only by |

## Section 2 — boundary set, read by hand

| Line | Verdict | Target | Owning doc | Entry as it stands |
| ---: | --- | --- | --- | --- |
| 71 | reads complete | pre-genesis | *undetermined* | Release-asset manifest signing owed before the first non-RC release |
| 86 | incomplete | pre-genesis | *undetermined* | TJ-2 — `CHALLENGE_RESPONSE_BLOCKS` is PINNED (2026-08-15); the freeze item |
| 131 | incomplete | pre-genesis | *undetermined* | `sweep_all` — deleted in WI-RPC-2b, no Shekyl-native surface; decide |
| 151 | reads complete | pre-genesis | *undetermined* | Workspace-wide `deny_unknown_fields` on the remaining wallet-RPC params |
| 184 | incomplete | pre-genesis | *undetermined* | Phase 4b: `get_transfers` OUTGOING filter is a no-op until an outgoing |
| 187 | incomplete | pre-genesis | *undetermined* | Phase 4b: build concurrency permit stays 1 — raising it is a rule-21 |
| 196 | incomplete | pre-genesis | *undetermined* | Alt-chain supply accumulation advances by the coinbase, not the emission |
| 223 | incomplete | pre-genesis | *undetermined* | Block-height-only `unlock_time`: native `Timelock`, a pruned-safe context-free |
| 253 | incomplete | pre-genesis | *undetermined* | Watchdog probe bytes: ephemeral in-memory held-bytes store — reversion |
| 259 | incomplete | pre-genesis | *undetermined* | F41 constant-work-on-Conceal: invariant NAMED + enforcement DECOMPOSED |
| 310 | incomplete | pre-genesis | *undetermined* | Re-derive genesis-sealed redundancy params against the integer backend |
| 322 | incomplete | pre-genesis | *undetermined* | `HoldingsUpdate` (partial-release/rebond) promoted to genesis scope + pre-seal |
| 325 | incomplete | pre-genesis | *undetermined* | Archival serve-credit / emission LMDB scans — bound the two unindexed table |
| 328 | incomplete | pre-genesis | *undetermined* | Emission-path micro-efficiency cluster — address with C-1 wiring / the schema |
| 343 | reads complete | pre-genesis | *undetermined* | Genesis ceremony tooling: `generate-genesis-address` CLI |
| 364 | incomplete | pre-genesis | *undetermined* | `RecoveredWalletOutput.key_image`: promote to `Option<KeyImage>` |
| 382 | incomplete | pre-genesis | *undetermined* | Revisit `rust/hard-coded-cryptographic-value` CodeQL suppression |
| 409 | incomplete | pre-genesis | *undetermined* | Consolidate hand-copied `10^9` / decimal-point constants onto the `shekyl-units` |
| 457 | incomplete | pre-genesis | *undetermined* | Market-bond wallet entry — `first_stake`'s genesis posture cannot |
| 460 | incomplete | pre-genesis | *undetermined* | Shard assignment for market staking — the `NoShardsAvailable` |
| 481 | incomplete | pre-genesis | *undetermined* | Serve-credit decision-site flip: Rust becomes the primary decision |
| 487 | reads complete | pre-genesis | *undetermined* | Remove or retain the orphaned `ActivityMetric.total_staked` observable |
| 550 | incomplete | pre-genesis | *undetermined* | PQC Multisig : Option-D residue left standing after the F-6 |
| 574 | incomplete | pre-genesis | *undetermined* | Resolution: FCMP++ historical-reference cutover via Stage 5 |
| 628 | incomplete | pre-genesis | *undetermined* | Relay: the `t_core` arrival harness — the witness this path has never |
| 640 | incomplete | pre-genesis | *undetermined* | Relay: re-derive `fluff_return_ms` once, when a degree distribution |
| 646 | incomplete | pre-genesis | *undetermined* | Fleet: arm readouts must record the per-sample series, not a pooled |
| 649 | incomplete | pre-genesis | *undetermined* | Relay: `full_travel_probability`'s cross-check holds `fluff_return_ms` |
| 652 | incomplete | pre-genesis | *undetermined* | Relay: `F'` may be per-POSTURE even though §89.2 correctly refused |
| 727 | reads complete | pre-genesis | *undetermined* | Hardening-pass commit 8 follow-up: WalletPrefs round-trip |
| 730 | incomplete | pre-genesis | *undetermined* | `tx_pool` / `blockchain_db` LMDB transactional wrapper — typed |
| 751 | incomplete | pre-genesis | *undetermined* | The GUI dials its daemon with nothing said — and a dial that says |
| 772 | reads complete | pre-genesis | *undetermined* | C++ JSON-RPC method-name rename: `wallet_*` → engine-shaped names |
| 814 | incomplete | pre-genesis | *undetermined* | 2d-1 SP-3 — borrow the block in the dual extractor instead of cloning per bonded scanner |
| 901 | reads complete | pre-genesis | *undetermined* | Foundation genesis-enumeration — legal / regulatory disclosure |
| 907 | reads complete | pre-genesis | *undetermined* | L14 read-credit soundness: per-(holder, shard), never shard-global |
| 916 | incomplete | pre-genesis | *undetermined* | Age-stratify the foundation floor AND the terminal subsidy toward |
| 919 | incomplete | pre-genesis | *undetermined* | L12 floor-decay schedule should be coupled to the growth↔entry |
| 928 | incomplete | pre-genesis | *undetermined* | Validate `prev_id` before attestation verify on the alt-chain path |

## Section 3 — found by parity, after a narrower definition missed them

The first pass defined "unclosed" as *fewer than two* `**` on the entry line.
That is wrong for an entry whose first bold closes and whose **second** bold
does not: the count is three, which is `>= 2`, so the entry passed. Two
entries are in that shape, and both are incomplete as written. The correct
predicate is **odd parity**, and it is what the gate uses.

This is also the reconciliation of the two counts this unit started with:
196 was mine under the narrow definition, 198 is the parity count, and 198 is
right. A neighbouring entry (line 1032, `**Closed (spec).**`) shows the form
these two were reaching for; the qualifier is not supplied here, because
supplying it would be inventing content.

Both entries have since been resolved and removed from `docs/FOLLOWUPS.md` by dev, so this section lists no rows. The finding is kept because it is why the predicate is parity and not a count, and because it records which definition produced which number — 196 mine, 198 correct.
