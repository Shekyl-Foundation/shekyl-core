# Region 2 / `WalletMetadata` — Consolidated Disposition

**Supersedes and replaces:** `region_2_design_review.md` (coexistence/Option-B design) and
`region_2_reframed.md` (decompose-and-retire reframing). Both are now fossils; delete them
to avoid false-corroboration. This document is the single authoritative record.

**Provenance of all citations:** full clone of `Shekyl-Foundation/shekyl-core`, `origin/dev`
@ `4b102dc31` (2026-06-18), all 22 remote branches and full history inspected.

**Verification status (2026-06-19):** Re-verified against `dev` after the Model D StakeEngine
and sealed `StakingBlock` work landed (PRs #159/#160, commits `c3538aa36` … `320785c88`). All
eight findings (F-1…F-8) hold; citation line numbers were refreshed to the current tree
(several had drifted by tens of lines) and the remote-branch count corrected to 22. The
staking audit (§2, F-1) is now **confirmed in landed code**: `StakingBlock` is a sealed
tier-4 `WalletLedger` block, not advisory TOML. **This PR executes the moves in §5:** it
deletes the orphan (Move 1), names tier 4 in WALLET_PREFS + rule 42 (Move 2), and removes
the dead C++ prefs FFI boundary (Move 3).

**Verdict:** The region-2 task is neither "make Rust a consumer" nor "decompose-and-retire."
It is **delete a fully-orphaned ~1,300-line module that the prefs system already routed
around**, plus name the missing storage tier so the next orphan can't form.

---

## 0. Two things are both called "region 2." Disambiguate first.

The single biggest source of confusion in this thread is a naming collision. There are two
distinct artifacts, and only one of them is real.

| Name in use | What it physically is | Status |
|-------------|----------------------|--------|
| **File-layout "region 2"** | The `.wallet` **state file** (the ledger), sealed under `wrap_key_region_2 = HKDF(file_kek, "shekyl-region2-aead-v1" \|\| addr)` | **Live, load-bearing, tier-4 wallet state.** Same physical thing the original prompt called "region 3." |
| **`WalletMetadata` "region 2"** | The identity+settings JSON in `shekyl-crypto-pq/src/wallet_state/` | **Orphan. Never sealed, never written, never read by any live path on any branch.** |

Sources for the collision:
- File-layout region 2 = state file: domain separator `HKDF_INFO_REGION2_AEAD_V1`
  (`rust/shekyl-crypto-pq/src/wallet_envelope.rs:159`), key derivation `derive_wrap_key_region_2`
  (`wallet_envelope.rs:500-508`); the state file is sealed at
  `rust/shekyl-engine-file/src/handle.rs:345` (and `:476`).
- `WalletMetadata` claims "region 2 of the `.wallet.keys` file":
  `rust/shekyl-crypto-pq/src/wallet_state/mod.rs:10`. This claim is aspirational; no code
  honors it.

Everything below concerns the **second** artifact — the orphan.

---

## 1. The orphan, proven at source

### 1.1 Zero live consumers

`WalletMetadata` / `IdentityBlock` / `SettingsBlock` are defined, version-gated,
secret-handling, property-tested — and wired to nothing.

- **No write path.** `WalletMetadata::to_json_bytes()` is called from **nowhere** outside its
  own test module. `git log --all -S to_json_bytes -- '*.rs'` returns exactly two commits
  (`1c271eb67`, `e6e5c0e40`) — both the module's *own creation*, neither a consumer.
- **No read path.** `WalletMetadata::from_json_bytes()`: same two commits, same conclusion.
- **No construction in any create path.** `new_for_creation()`: same. `WalletFile::create`
  (`handle.rs:296`) seals the ledger via `seal_state_file` (`handle.rs:335`), never a
  metadata JSON.
- **`assemble()` never receives it.** It takes `WalletLedger` (tier 4) + `WalletPrefs`
  (tier 3) only: `rust/shekyl-engine-core/src/engine/lifecycle.rs:689`.
- **Nothing outside the module imports its types.** A workspace grep for `wallet_state::`,
  `WalletMetadata`, `SettingsBlock`, `IdentityBlock` outside
  `shekyl-crypto-pq/src/wallet_state/` returns only (a) the unrelated `ShekylWalletMetadata`
  C-FFI struct (which reads **region 1**, not this JSON — see §1.3) and (b) two prose
  doc-comments (`shekyl-engine-state/src/error.rs`, `staking_block.rs`) — no code consumer.

### 1.2 Confirmed across all remote branches

Per-branch scan of every remote tip for a `WalletMetadata` consumer in any engine / wallet
load path (`shekyl-engine-core`, `shekyl-engine-file`, `src/wallet`): **empty on every
branch.** No in-flight commit is mid-wiring it. The orphan is not a work-in-progress; it is
abandoned. (One false positive: `main`, far behind `dev`, carries
`pub use wallet_state::WalletState` — that is **shekyl-scanner's own** unrelated
`wallet_state.rs` module, not the crypto-pq orphan.)

### 1.3 The C-FFI `ShekylWalletMetadata` is a different, also-doomed thing

`ShekylWalletMetadata` (`rust/shekyl-ffi/src/engine_file_ffi.rs:219`, 96-byte layout pinned by
a `static_assert` at `:253`, mirrored in `src/shekyl/shekyl_ffi.h:1433`) is a flat C struct
populated from **region 1** + AAD — `network`, `capability_mode`, `seed_format`,
`creation_timestamp`, `restore_height_hint`, `expected_classical_address`
(`engine_file_ffi.rs:792-802`, reading `w.inner.capability()` etc.). It does **not** touch the
`WalletMetadata` JSON. Its only C++ caller is `wallet2.cpp:5320`, which is deleted in the
cutover. It is irrelevant to the orphan's disposition except as a name-collision hazard.
(The struct's source file is `engine_file_ffi.rs`; the older name `wallet_file_ffi.rs` survives
only in stale code comments.)

### 1.4 How the orphan formed (the archaeology)

The history is unambiguous and exonerates the current design — the orphan is a *superseded
first draft*, not a planned component:

1. **`1c271eb67` / `e6e5c0e40` (2a / 2a.1, 2026-04-23 07:21):** created a monolithic
   `wallet_state.rs` (1,210 lines), then split it into a `wallet_state/` directory with
   `identity`, `settings`, `ledger`, `bookkeeping`, `primitives`. This was the original
   plan to put settings in the keys file.
2. **`52b709cac` (2k.0, 2026-04-23 13:17) — six hours later:** `docs: wallet preferences
   categorization & storage policy` lands. WALLET_PREFS reclassifies the entire settings
   surface into the three-layer model (hardcoded / TOML / CLI), explicitly to *stop* storing
   settings as a sealed monolith.
3. **`5a6864fd7` (2k.1):** `NetworkSafetyConstants` — settings' fund-relevant half goes to
   tier 1.
4. **`58622c848` (2k.3), `d1c385f41` (2k.4):** the prefs crate + FFI — the advisory half goes
   to tier 3. (Landed as `shekyl-wallet-prefs`; later renamed `shekyl-engine-prefs` at
   `a30cbfd27`.)
5. **`a30cbfd27`:** `engine-prefs: remove subaddress_lookahead bucket` — prefs actively
   *curated away* from the metadata shape ("Monero-era lookahead window deleted at V3.0").
6. **The `ledger.rs` and `bookkeeping.rs` halves of `wallet_state/` are gone from `dev`**
   (pruned at `b4cf3301e`) — they migrated to `shekyl-engine-state` as tier-4 blocks. Only
   `identity` + `settings` + `mod` + `primitives` remain, stranded.

So the four-tier decomposition WALLET_PREFS describes **already happened in code**: ledger →
tier 4 (`shekyl-engine-state`), settings → tier 1/3 (`NetworkSafetyConstants` / `engine-prefs`),
identity → region-1 AAD. The `2k` work routed around the `2a` module without ever deleting it.
`WalletMetadata` is the fossil left in the strata.

---

## 2. The four-tier storage model (canonical)

This is the model that resolves both the region-2 question and the earlier staking (tier-4)
decision. It is the durable output of this thread, now named in
[`WALLET_PREFS.md` §2](./WALLET_PREFS.md).

| Tier | Where | Who writes | Integrity | Failure mode | Reset-to-default safe? |
|------|-------|-----------|-----------|--------------|------------------------|
| **1 — Hardcoded constants** | `NetworkSafetyConstants` (Rust source, per network) | Release only | Compile-time | N/A | Yes (network-fixed) |
| **2 — CLI-ephemeral** | command-line flags | User at invocation | None (unpersisted) | Loud `WARN` on open | Yes (not stored) |
| **3 — Advisory TOML** | `<base>.prefs.toml` + `.hmac` | GUI / CLI / editor | HMAC-SHA256 | Quarantine + warn → defaults | **Yes — this is the entry criterion** |
| **4 — Sealed wallet state** | `.wallet` (file-layout region 2) blocks | Engine (chain-reconciled) | AEAD under state-wrap-key | **Refuse-to-load**, strict version | **No — losing it loses/endangers funds** |

**The decision procedure (this is the fix for the whole class of bug):**

> 1. **Does resetting this field to its default lose or endanger funds?**
>    → **Tier 4.** Stop. (Do not pass go; do not ask "is it user-tunable.")
> 2. Is it network-fixed with no legitimate per-wallet variance? → **Tier 1** (+ Tier 2 for
>    session overrides).
> 3. Is it user-tunable and *not* fund-threatening? → **Tier 3.**

WALLET_PREFS originally encoded only steps 2–3 and baked in the hidden assumption
*user-tunable ⟹ not fund-threatening*. That assumption has no slot for **user-chosen,
persistent, fund-threatening state** — which is exactly what `staking_enabled` / `p_slot` /
the bonded-set are, and exactly why they went to tier 4 (file-layout region 2 — what the
original prompt called "region 3"). A literal reading of the old three-layer WALLET_PREFS
files `staking_enabled` into tier-3 advisory TOML, where a tamper event quarantines it and
loads a default that **bricks unbonding** — the funds-loss the staking decision correctly
rejected. Tier 4 is the answer; it was simply never named (until the amendment this PR makes
— Move 2).

**Landed confirmation (Model D, `dev`):** the `StakingBlock` work implements exactly this.
`StakingBlock` is the fifth field of `WalletLedger`
(`rust/shekyl-engine-state/src/wallet_ledger.rs:122-126`) — inside file-layout region 2 —
sealed with XChaCha20-Poly1305 under `derive_wrap_key_region_2` via `WalletFile::save_state`
(`handle.rs:503-521`), strict-version-gated (`StakingBlock::check_version`,
`staking_block.rs:207-216`; `WALLET_LEDGER_FORMAT_VERSION` bumped 7→8), schema-snapshotted,
and **refuse-to-load** on drift. A grep of the `shekyl-engine-prefs` crate for `staking` /
`p_slot` / `bonded` is empty — zero tier-3 coupling. The trap this section warns about cannot
occur on that wiring.

---

## 3. Findings & dispositions

Severity-ordered. Reopen criteria per rule 21.

### F-1 [HIGH → process; amendment included in this PR] — WALLET_PREFS and rule 42 lacked tier 4; the next funds-relevant toggle would be misfiled

**This is the only finding that produces durable new work.** Everything else is one-time cleanup.

- **Substrate:** WALLET_PREFS §2 named three layers, and its own rule — "adding a new
  wallet-tunable field requires explicitly choosing a layer" (WALLET_PREFS §2) — offered a
  three-wide menu that omits sealed funds-load-bearing state. Rule `42-serialization-policy.mdc`
  enforces version pairing for persisted (tier-4) blocks but did not pin *placement*. The
  staking trap and the `max_reorg_depth` misfile (§F-3) are both instances.
- **Disposition:** Amend WALLET_PREFS §2 to add **Tier 4 — sealed funds-load-bearing wallet
  state (file-layout region 2 / `shekyl-engine-state` blocks): AEAD-sealed, strict version,
  refuse-to-load.** Amend rule 42 to pin the **funds-first decision order**
  ("does reset lose/endanger funds?" precedes "is it user-tunable?"). **Done in this PR (Move
  2): WALLET_PREFS §2 four-layer model + §2.4 + decision procedure; rule 42 "Funds-first tier
  placement".**
- **Reopen:** Closed when WALLET_PREFS §2 names tier 4 and rule 42 encodes the funds-first
  order — **both now done in this PR.** Reopen only if a field appears that is funds-relevant
  yet *not* chain-reconciled (would imply a fifth category — none known today).

### F-2 [HIGH → resolved: delete] — The `wallet_state` module is a fully-orphaned fossil

- **Substrate:** §1.1–§1.4. Zero consumers on `dev` or any remote branch; ~1,300 lines
  (`mod.rs` 389, `settings.rs` 546, `identity.rs` 180, `primitives.rs` 187, per `origin/dev`);
  still exported at `shekyl-crypto-pq/src/lib.rs:69` (`pub mod wallet_state;`) but imported by
  nothing outside its own directory.
- **Disposition:** **Delete the module wholesale** — executed in this PR, well before the
  cutover: `wallet_state/{mod,identity,settings,primitives}.rs` and the `lib.rs:69` export. No
  reader to repoint, no data migration (nothing was ever sealed in this shape), no version-bump
  cost beyond test-wallet recreation (pre-genesis, free).
- **Why delete rather than wire up:** Keeping it is the **laundering risk** — see F-4. Wiring
  it up would re-introduce the exact sealed-settings-monolith WALLET_PREFS exists to abolish.
- **Reopen:** Reopen only if the pre-delete check (F-5) surfaces an unmerged branch that
  consumes it. None found in this full-clone scan.

### F-3 [HIGH → resolved: inert, delete with module] — `max_reorg_depth` misfiled in the orphan, but the live read uses the correct tier-1 source

- **Substrate (the misfile):** `settings.rs:255-261` defines `ScanSafetySettings::max_reorg_depth`
  as a persisted `u64`, default **100** (`settings.rs:62`), strict-version-gated. WALLET_PREFS
  §3.1 says it is **tier-1 base** (mainnet 10 / testnet 6 / stagenet 10) + **tier-2 CLI override**.
  The `settings.rs:38-41` comment rationalizes the misfile by calling it a "scan margin, not a
  consensus parameter" — the reclassification-to-justify-a-knob pattern WALLET_PREFS §1 warns of.
- **Substrate (the live read is correct):** the tier-1 source is resolved by
  `effective_max_reorg_depth` (`overrides.rs:87-90`), which returns the CLI override if present
  and otherwise `NetworkSafetyConstants::for_network(network).max_reorg_depth`. The in-state
  submit-safety harness `submit_pending_tx_in_state` (`pending.rs:657-677`, a `#[cfg(test)]`
  function) reads the same source. The constants are 10/6/10 (`safety_constants.rs:89,101,113`).
  **Nothing reads `ScanSafetySettings::max_reorg_depth`** — grep for `scan_safety` /
  `ScanSafetySettings` outside `settings.rs` is empty.
- **Net:** The misfile is **real but inert** — the dangerous default-100 path is dead code.
  The tier-1+2 model is already fully wired and live and correct.
- **Disposition:** No live fix needed. The field dies with the module (F-2). Tracking note:
  the doc-level disagreement (WALLET_PREFS base 10 vs orphan default 100) evaporates once the
  orphan is deleted; the constant is the sole survivor.
- **Reopen:** Reopen if a future `assemble()` wiring is proposed that reads
  `ScanSafetySettings` — that proposal is rejected on sight (tier-1 state does not belong in a
  settings struct).

### F-4 [HIGH → the reason for "delete now, not after cutover"] — The cutover launders the fossil into intentional design

- **Substrate:** The cutover deletes all C++ wallet code and transfers ownership to Rust.
  If the cutover ports `wallet_state` as-is into the Rust-only world (or merely leaves it
  exported), the orphan stops being "inherited residue we haven't swept" and becomes
  "intentional Rust-owned design." Its version gates, secret-handling, and mis-defaulted
  `max_reorg_depth` (F-3) gain false authority. This is the fossil-corroboration failure mode,
  except the fossil is now load-bearing-looking and fund-adjacent.
- **The cheap-fix window closes at the cutover.** Pre-genesis, deleting the module costs only
  test-wallet recreation (no migration code — rules 15/60). That is free now and never this
  cheap again; once anything reads it, deletion needs a migration story.
- **Disposition:** The module deletion (F-2) must land **in or before** the cutover, not as
  follow-up. "Rust-owned by nature" is the argument *for* getting the shape right at the moment
  of ownership transfer, not for inheriting the orphan unexamined.
- **Reopen:** N/A — this is a sequencing constraint on F-2, not an independent finding.

### F-5 [MEDIUM → single pre-delete gate] — Confirm no unmerged work consumes the module before deleting

- **Substrate:** This full-clone scan covers all remote branches. It cannot see local
  branches on a contributor's machine that were never pushed.
- **Disposition:** Before the delete commit, the cutover author runs
  `git log --all -S "from_json_bytes" -- '*.rs'` (and `to_json_bytes`, `new_for_creation`) on
  their local clone with all working branches present, and confirms the result still shows only
  `1c271eb67` / `e6e5c0e40`. The drafter/developer should also confirm no local WIP imports
  `wallet_state::`. One check; if clean, delete.
- **Status (2026-06-19):** Re-run on `dev` after Model D landed — across all remote + local
  branches and the working tree — **clean**: all three symbols return only `1c271eb67` /
  `e6e5c0e40`, and no outside-module `wallet_state::` code consumer exists.
- **Reopen:** Closed by a clean local-branch scan at delete time — done for this PR.

### F-6 [MEDIUM → dies with module, with one forward caveat] — Secrets serialized into the orphan's JSON

- **Substrate:** `settings.rs:295` (`OriginalKeys::original_view_secret_key`,
  `Zeroizing<[u8;32]>`, hex-serialized) and `settings.rs:323`
  (`BackgroundSyncConfig::custom_background_key`, `Option<Zeroizing<[u8;32]>>`). Secret keying
  material serialized into a settings JSON — categorically the wrong home, but moot because the
  JSON is never written.
- **Disposition:** Both die with the module (F-2). **Forward caveat:** if background-sync is in
  V3.0 scope, `custom_background_key` needs a *real* sealed home spec'd against region 1 (or
  derived from `file_kek`), not a revived settings store. Confirmed not in scope today
  (WALLET_PREFS §3.3 marks `background_sync_type` out of V3.0 scope; `custom_background_key` has
  zero consumers outside `settings.rs`). That is a forward feature spec, not a region-2
  retirement blocker.
- **Reopen:** Reopen as a *new* spec item if/when background-sync lands and requires a persisted
  per-wallet sync key. Tracked separately from this disposition.

### F-7 [LOW → resolved: nothing to place] — There is no `capability_mode` residual

- **Substrate:** Earlier framing nominated `capability_mode` as a region-2 field needing
  placement with the keys. It is already there: `mode_byte` is the first byte pushed into
  **region 1** plaintext (`wallet_envelope.rs:802`), surfaced via `w.inner.capability()`
  (`engine_file_ffi.rs:792-802`). `IdentityBlock` has no `capability_mode` field
  (`identity.rs:63-95`).
- **Disposition:** No action. Recorded to prevent the hypothesis from recurring.

### F-8 [LOW → resolved: stale docs] — Module docs and WALLET_PREFS reference an obsolete world

- **Substrate:** `wallet_state/mod.rs:6-24` and `identity.rs:6-18` describe the module as the
  live region-2 reader; WALLET_PREFS §1 describes the legacy monolith as if it still exists.
  Both predate the `2k` decomposition.
- **Disposition:** Deleting the module (F-2) removes the stale module docs. WALLET_PREFS §1 is
  amended alongside F-1 to note the decomposition is complete and the sealed-settings monolith
  no longer exists in code (done in this PR).

---

## 4. Retractions (clean)

| Retracted | Round | Why it was wrong |
|-----------|-------|------------------|
| Option B (Rust owns, C++ reads region 2 via FFI) | Review 1 | No persisting C++ consumer; C++ deleted in cutover. |
| Two-reader version-coordination contract (cbindgen-shared constants) | Review 1 | One reader (Rust); after cutover there is no second reader to coordinate with. |
| PR-Region2-Reader / PR-FFI-Getters / PR-Settings-Writer sub-PRs | Review 1 | Build a reader for an orphan that should be deleted. |
| "Decompose-and-retire reconciliation" as the task | Review 2 | Decomposition already happened in `2k`; the task is *delete the residue*, not perform the decomposition. |
| `capability_mode` as a region-2 residual to place | Review 2 | Already in region 1 (F-7). |
| `SettingsBlock` as "the legacy monolith" | Review 2 | It is the curated V3 residual; the monolith's fund-threatening fields were already dropped at `2a` and the rest re-homed at `2k`. |

---

## 5. The moves that close this thread

**Move 1 — Delete the orphan (F-2), gated by one local-branch check (F-5), sequenced into or
before the cutover (F-4).** Remove `shekyl-crypto-pq/src/wallet_state/` and its `lib.rs:69`
export. No reader to repoint; no migration; pre-genesis so the version cost is test-wallet
recreation only. Secrets and the mis-defaulted `max_reorg_depth` die with it. **Executed in
this PR**, with the two external dangling intra-doc links
(`shekyl-engine-state/src/{error.rs,lib.rs}`) repointed.

**Move 2 — Name tier 4 in WALLET_PREFS and rule 42 (F-1).** Add the sealed-funds-bearing tier
and the funds-first decision order, so the next funds-relevant toggle cannot be reflexively
filed into advisory TOML and silently default-reset into a funds-loss. This is the only durable
deliverable; the staking trap and the `max_reorg_depth` misfile are both symptoms of its
absence. **Executed in this PR** (WALLET_PREFS §2 four-layer model + §2.4 + decision procedure;
rule 42 "Funds-first tier placement").

**Move 3 — Remove the dead C++ prefs (tier-3) FFI boundary.** Prefs are already Rust-owned
end to end: the engine consumes `shekyl-engine-prefs` natively (`load_prefs`/`save_prefs`),
and the C++ `wallet2::rewrite` path is a logged no-op that defers to `WalletPrefs`. The
`shekyl_engine_prefs_get/set_json` FFI shim (plus its tests) and the name-mismatched,
fully-orphaned `shekyl_wallet_prefs_*` C declarations in `shekyl_ffi.h` had **zero callers**
in core, GUI, or mobile (grep-verified). Deleted both sides as a Phase 5 pre-emption — the
precedent the `shekyl_ffi.h` `save_as` section records for the per-block ledger FFI. The
live `SHEKYL_WALLET_ERR_PREFS` wire code is retained (still mapped from
`WalletFileError::Prefs`). "Making the Rust path the path" was never a migration — the logic
was already in Rust; this move was a deletion.

Everything else — coexistence models, FFI getters, version contracts, region-2 readers — was
scaffolding for a building that was already demolished. The region-2 work is a sweep, not a
build.
