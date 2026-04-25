# Shekyl Wallet Preferences — Categorization & Storage Policy

**Status:** design spec. No normative code reference yet; this document
is the contract that commits `2k.1` … `2k.5` implement.
**Scope:** the ~30 user-tunable wallet settings inherited from the
Monero-lineage `wallet2` `keys_file_data` blob, restructured for Shekyl
V3.0 according to their attack-surface profile.
**Related specs:**
[WALLET_FILE_FORMAT_V1.md](./WALLET_FILE_FORMAT_V1.md) ·
[POST_QUANTUM_CRYPTOGRAPHY.md](./POST_QUANTUM_CRYPTOGRAPHY.md).
**Related rules:**
[30-cryptography.mdc](../.cursor/rules/30-cryptography.mdc) ·
[35-secure-memory.mdc](../.cursor/rules/35-secure-memory.mdc) ·
[40-ffi-discipline.mdc](../.cursor/rules/40-ffi-discipline.mdc) ·
[80-usability.mdc](../.cursor/rules/80-usability.mdc) ·
[82-failure-mode-ux.mdc](../.cursor/rules/82-failure-mode-ux.mdc).

## 1. Motivation

`wallet2.cpp::get_keys_file_data` serializes a monolithic rapidjson blob
carrying ~50 fields: the account seed, `seed_language`, and a pile of
user-preference settings (`ask_password`, `auto_refresh`,
`m_refresh_from_block_height`, `default_priority`,
`subaddress_lookahead_*`, `max_reorg_depth`, `key_reuse_mitigation2`,
`inactivity_lock_timeout`, `track_uses`, `export_format`, …). Everything
goes through the same AEAD, the same versioning story, and the same
refuse-to-load bar as the cryptographic seed itself.

That shape is wrong for Shekyl V3:

- **It conflates distinct attack surfaces.** Cosmetic knobs like
  `default_decimal_point` share a persistence mechanism with
  consensus-relevant switches like `max_reorg_depth`.
- **It conflates distinct evolution patterns.** Cosmetic prefs change
  often and must round-trip unchanged. Consensus-relevant fields must
  refuse-to-load on schema drift (the "no silent migration" rule). The
  same file cannot honor both contracts.
- **It exposes fund-threatening knobs to everyone.** A GUI setting that
  disables `key_reuse_mitigation2` or lowers `max_reorg_depth` is a
  footgun with no legitimate common use case.
- **It perpetuates Monero's "expose every knob to the user"
  philosophy** that Shekyl V3 otherwise rejects (no base58, no Electrum,
  no pre-V3 formats).

This document pins the replacement.

## 2. Three-layer storage model

Every setting lands in exactly one of three layers:

| Layer                  | Where                                       | Who modifies         | Integrity                     | Evolution policy                                    |
|------------------------|---------------------------------------------|----------------------|-------------------------------|-----------------------------------------------------|
| **Hardcoded**          | `shekyl_wallet_state::safety_constants`     | Rust source, per network | Compile-time                  | Changed by release; never by a user or a data file. |
| **Plaintext TOML**     | `<base>.prefs.toml` + `<base>.prefs.toml.hmac` | GUI, CLI, or text editor | HMAC-SHA256 over file bytes   | Add/remove fields freely; missing fields use defaults. |
| **CLI-ephemeral override** | `shekyl-cli` command-line flags         | User at invocation time  | None (never persisted)        | N/A — not stored.                                   |

The categorization is per-field and not negotiable. Rule
`42-serialization-policy.mdc` will pin this at the workspace level:
**adding a new wallet-tunable field requires explicitly choosing a layer
and, for TOML or CLI-override, writing the rationale in this document.**

### 2.1 Hardcoded (consensus-relevant, safe defaults)

Baked into the binary, per network. Users cannot change these through
any normal workflow.

- **Principle:** any tampering with these values threatens funds
  (wallet accepts a reorg that should be rejected, wallet reuses view
  secrets across txs, wallet silently skips scanning, …).
- **Storage:** `const fn` constructors on `NetworkSafetyConstants`.
- **Why not CLI-override for all of them:** "always on" is safer than
  "on by default, user can disable." For fields with zero legitimate
  reason to deviate, removing the knob removes the attack surface.

### 2.2 Plaintext TOML with HMAC

Cosmetic, operational, device, RPC, and lookahead settings. Users edit
through the GUI, through `shekyl-cli config …`, or by hand with a text
editor.

- **Principle:** tampering is detectable but not fund-threatening.
  Cosmetic and operational UX should be trivially inspectable by the
  user; if they can't read their own `prefs.toml`, it doesn't need to
  be secret.
- **Storage:** `<base>.prefs.toml` (the TOML body) plus
  `<base>.prefs.toml.hmac` (32 bytes of HMAC-SHA256). Co-located with
  `.wallet.keys` and `.wallet`.
- **Integrity key:**
  ```
  prefs_hmac_key = HKDF-Expand(
      prk  = file_kek,
      info = b"shekyl-prefs-hmac-v1" || expected_classical_address,
      L    = 32
  )
  ```
  Deriving from `file_kek` means the HMAC key is only available while
  the wallet is unlocked — tampering while locked is detected at the
  next open. Binding to `expected_classical_address` defeats
  cross-wallet pref-file swaps even in the unlikely event two wallets
  share a `file_kek`; same pattern as `seed_block_tag` binding
  `.wallet` to `.wallet.keys` in `WALLET_FILE_FORMAT_V1`.
- **Failure semantics** — see §5.
- **Schema:** defined by the `shekyl-wallet-prefs` crate.
  `#[serde(deny_unknown_fields)]` on every nested struct; file-size
  cap at parse time; per-field rejection messages for any name that
  collides with a CLI-override field name (see §6).

### 2.3 CLI-ephemeral overrides

Consensus-relevant **runtime** overrides. Available only via
`shekyl-cli` command-line flags; never persisted; never exposed in
GUI.

- **Principle:** anything a user might legitimately want to set "just
  for this session" (chain-analysis work, testing, one-shot import
  with a known starting height) is a flag, not a stored preference.
  The absence of persistent storage is the defense against
  attacker-seeded overrides.
- **Storage:** none. `SafetyOverrides` is a request-scoped struct,
  `#[derive(Debug)]` but not `Serialize`, passed by value into
  `WalletFile::open`.
- **Logging:** every active override emits a `WARN`-level log line at
  open time naming the field, the override value, and the network
  default. Loud by construction.
- **GUI exposure:** none. The GUI constructs `SafetyOverrides::none()`
  unconditionally. Advanced workflows require `shekyl-cli`.

## 3. Field-by-field categorization

The table below fixes which layer each legacy `wallet2` field lands
in. Rows are grouped by layer for readability.

### 3.1 Hardcoded constants

Implemented in `shekyl_wallet_state::safety_constants::NetworkSafetyConstants`
(commit 2k.1). Fields marked **invariant** admit no CLI override at any
layer; fields marked **base** supply the per-network default that the
`SafetyOverrides` struct from §3.3 overlays on at wallet open.

| Field                              | Mainnet | Testnet | Stagenet | Kind      | Rationale |
|------------------------------------|---------|---------|----------|-----------|-----------|
| `key_reuse_mitigation2`            | `true`  | `true`  | `true`   | invariant | Defense against view-key-reuse linkability; always on. No legitimate reason to disable in normal operation. Research use cases run debug builds with a source-level flag. |
| `max_reorg_depth`                  | `10`    | `6`     | `10`     | base      | Minimum confirmations before a transfer is final. Testnet is tuned for fast iteration; stagenet mirrors mainnet because its purpose is to exercise mainnet parameters. CLI override: see §3.3. |
| `default_skip_to_height`           | `0`     | `0`     | `0`      | base      | One-shot import hint (starting height for the first scan). CLI override: see §3.3. Once a `SyncStateBlock` exists its stored `restore_from_height` supersedes this default. |
| `default_refresh_from_block_height`| `0`     | `0`     | `0`      | base      | Refresh cursor used when the wallet opens without a `SyncStateBlock` (lost-`.wallet` recovery path). CLI override: see §3.3. |

**Monero-lineage fields deliberately absent.** `segregation_pre_fork_outputs`
and `segregation_height` reflect Monero's post-key-reuse-mitigation fork
segregation — a concept that does not apply to a V3 fresh-start wallet
where no pre-fork output set exists. Per rule
`60-no-monero-legacy.mdc`, these fields are not carried forward.

### 3.2 Plaintext TOML (HMAC-integrity)

#### Cosmetic (Bucket 1)

| Field                          | Default       | Rationale |
|--------------------------------|---------------|-----------|
| `default_decimal_point`        | `12`          | Display only. |
| `show_wallet_name_when_locked` | `false`       | Cosmetic. |
| `setup_background_mining`      | `prompt`      | UX flow. |
| `default_priority`             | `medium`      | Fee priority default; trivial impact if tampered. |
| `confirm_backlog`, `confirm_backlog_threshold` | `true, 4096` | UX confirmation. |
| `confirm_export_overwrite`     | `true`        | UX confirmation. |
| `always_confirm_transfers`     | `true`        | UX confirmation. |
| `export_format`                | `binary`      | File format for exports; cosmetic. |

#### Operational (Bucket 2)

| Field                          | Default       | Rationale |
|--------------------------------|---------------|-----------|
| `refresh_type`                 | `Optimized`   | Visibility trade-off, not consensus. Tampering to `NoCoinbase` loses mining-reward visibility but does not threaten chain validation. |
| `auto_refresh`                 | `true`        | UX; scan-on-open. |
| `auto_low_priority`            | `false`       | Fee fallback. |
| `track_uses`                   | `false`       | Local forensic info. |
| `store_tx_info`                | `true`        | Local audit trail. |
| `min_output_count`             | `0`           | Coin-selection floor; privacy, not consensus. |
| `min_output_value`             | `0`           | Coin-selection floor. |
| `ignore_outputs_above`         | `u64::MAX`    | Coin-selection cap. |
| `ignore_outputs_below`         | `0`           | Coin-selection cap. |
| `merge_destinations`           | `false`       | Privacy regression if flipped to `true`; not consensus. |
| `inactivity_lock_timeout`      | `0` (off, timeout in minutes when non-zero) | Runtime session lock. HMAC catches tampering while locked. |

#### Device (Bucket 4)

| Field                     | Default  | Rationale |
|---------------------------|----------|-----------|
| `device_name`             | `""`     | HW-wallet routing hint; tampering re-derives different keys, but envelope AAD's `expected_classical_address` cross-check catches the mismatch at open. |
| `device_derivation_path`  | `""`     | Same as above. |

#### RPC (Bucket 5)

| Field                                | Default | Rationale |
|--------------------------------------|---------|-----------|
| `persistent_rpc_client_id`           | random  | Stable client identifier for RPC payments; tampering merely breaks RPC pay, not funds. |
| `auto_mine_for_rpc_payment_threshold`| `0`     | If enabled, bounded auto-mine for RPC credits. |
| `credits_target`                     | `0`     | RPC credit balance target. |

#### Subaddress lookahead (Bucket 6)

| Field                          | Default        | Rationale |
|--------------------------------|----------------|-----------|
| `subaddress_lookahead.major`   | `5`            | Visibility trade-off (too small ⇒ miss incoming; too large ⇒ CPU DoS). Not consensus. Some HW-wallet workflows need to bump this, so TOML-persistent is right. |
| `subaddress_lookahead.minor`   | `200`          | Same. |

#### Display-only identity

| Field                          | Default  | Rationale |
|--------------------------------|----------|-----------|
| `seed_language`                | `"english"` | BIP-39 wordlist for displaying the seed back to the user. Master-seed bytes are invariant; language is strictly display. Not in any of Buckets 1-6 above because it is set-once-at-creation; listed here for completeness. |

### 3.3 CLI-ephemeral overrides

| Field                        | Network default         | Override flag                               | Rationale |
|------------------------------|-------------------------|---------------------------------------------|-----------|
| `max_reorg_depth`            | `10` (mainnet)          | `--max-reorg-depth N`                       | Advanced chain-analysis or test workflows may legitimately raise or lower this. |
| `skip_to_height`             | `0`                     | `--skip-to-height N`                        | One-shot bootstrap parameter; after the first scan `SyncStateBlock.restore_from_height` takes over. |
| `refresh_from_block_height`  | `0`                     | `--refresh-from-block-height N`             | Same category as `skip_to_height`: one-shot import hint. Not persistent in the new world. |

**`ask_password`** is dropped from the wallet-file surface entirely.
It becomes a pure `shekyl-cli` runtime flag (`--password-prompt never|on-action|to-decrypt`) with no persisted counterpart; the GUI uses `on-action` unconditionally.

### 3.4 Dropped entirely

Fields from `wallet2`'s `get_keys_file_data` that are not represented
anywhere in the new surface:

| Field                    | Disposition |
|--------------------------|-------------|
| `encrypted_secret_keys`  | The envelope itself is AEAD-encrypted; this redundant marker is meaningless. |
| `original_keys_available`| Superseded by capability modes (`FULL` / `VIEW_ONLY` / `HARDWARE_OFFLOAD`). |
| `watch_only`             | Superseded by `capability_mode == VIEW_ONLY`. |
| `background_sync_type`   | Not part of V3.0 scope; re-introduce as a TOML field if and when the feature ships. |
| `nettype`                | Not a pref — part of wallet identity, committed in `.wallet.keys` AAD. |

No silent migration from legacy wallet2 blobs. Per the "not a Monero
port" directive, V3 wallets are created fresh; there is no upgrade
path and none is planned.

## 4. File naming and lifecycle

### 4.1 Companion paths

For a wallet whose keys file lives at `P.wallet.keys` and state file at
`P.wallet`, prefs files live at:

```
P.prefs.toml        — TOML body, ≤ 64 KiB, strict schema
P.prefs.toml.hmac   — exactly 32 bytes, HMAC-SHA256 of the TOML body
```

All four files share the same basename `P`. Renaming the wallet is a
basename rename applied to the full cluster:

```
mv foo.wallet      bar.wallet
mv foo.wallet.keys bar.wallet.keys
mv foo.prefs.toml  bar.prefs.toml
mv foo.prefs.toml.hmac bar.prefs.toml.hmac
```

A future `shekyl-cli rename` helper will automate this atomically. The
orchestrator refuses to open a wallet whose prefs file exists under a
stale basename (the HMAC will not validate; §5 describes the recovery).

No wallet UUID is carried in any envelope. Adding one would be a
format change; the basename-match model is sufficient because the
wallet is already a multi-file artifact that users move as a unit.

### 4.2 First-open bootstrap

On wallet creation, `P.prefs.toml` and `P.prefs.toml.hmac` are **not**
written. They are created on the first explicit pref-modifying
operation (GUI "Settings" save, `shekyl-cli config set …`), or on the
first open of a `.wallet.keys` that already exists without a prefs
companion (the "cold clone" scenario).

On every subsequent open, the prefs file is located by basename and
verified.

### 4.3 Atomic writes

Same pattern as `.wallet` saves:

```
write P.prefs.toml.tmp  ; fsync ; write P.prefs.toml.hmac.tmp ; fsync
rename P.prefs.toml.tmp      → P.prefs.toml
rename P.prefs.toml.hmac.tmp → P.prefs.toml.hmac
fsync parent dir
```

Crash between the two renames leaves a body-without-matching-HMAC,
which §5 treats as a tamper event. The fix is self-healing: the next
successful save rewrites both files together.

## 5. Failure semantics

The prefs file is **advisory**. Safety is delivered by hardcoded
defaults (§2.1), not by pref-file integrity. Consequences:

| Condition                          | Behavior at open                                                                                                                            |
|------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| Neither `.prefs.toml` nor `.hmac`  | Silent. Load hardcoded defaults. Do not create the file until the user modifies a pref.                                                     |
| `.prefs.toml` missing, `.hmac` present | Tamper. Quarantine the orphan `.hmac`. Load hardcoded defaults with a `WARN` line.                                                      |
| `.prefs.toml` present, `.hmac` missing | Tamper. Quarantine the `.toml`. Load hardcoded defaults with a `WARN` line.                                                             |
| HMAC mismatch                      | Tamper. Quarantine both files. Load hardcoded defaults with a `WARN` line.                                                                  |
| TOML parse failure (unknown field, size cap, syntax) | Tamper. Same quarantine + `WARN`.                                                                                         |
| HMAC valid, TOML valid             | Load prefs. No log line.                                                                                                                     |

Quarantine filename format:

```
P.prefs.toml.tampered-<unix_seconds>
P.prefs.toml.hmac.tampered-<unix_seconds>
```

On collision (same wall-clock second), append a monotonic counter:

```
P.prefs.toml.tampered-1730000000
P.prefs.toml.tampered-1730000000.1
P.prefs.toml.tampered-1730000000.2
```

Forensic files are never clobbered. They accumulate until the user
deletes them. A future `shekyl-cli prefs status` command will list
quarantined files so users can inspect and reap them.

**Why advisory, not refuse-to-load?** Ledger data must refuse silent
migration because silent migration is an attack surface that affects
funds. Cosmetic/operational prefs have no such property; refusing to
open a wallet over `default_decimal_point` tampering is user-hostile.
The design splits the contract: funds-relevant state is
refuse-to-load, UX state is quarantine-and-warn.

## 6. TOML schema strictness

### 6.1 Parser rules

- `#[serde(deny_unknown_fields)]` on every `struct` and `enum`.
- File-size cap enforced at read time: 64 KiB. Files larger than this
  fail the same way as a tamper event. Real prefs are < 1 KiB.
- UTF-8. No BOM. Newline-terminated bodies are fine; trailing
  whitespace is accepted.
- Parse is performed once at open time and once at save time. The
  HMAC covers the exact bytes that were parsed or written.

### 6.2 Per-field rejection messages for Bucket-3 names

If the TOML body contains a top-level or nested field whose name
collides with a CLI-override name, the parser fails with a
per-field error message naming the CLI flag. Example:

```
Error: prefs.toml contains `max_reorg_depth`, which is not a
persistent preference. Advanced chain-reorganization depth is a
runtime-only override.

Use:
    shekyl-cli --max-reorg-depth N <command>

See docs/WALLET_PREFS.md §3.3 for the full preference/override
distinction.
```

One such message per Bucket-3 field name. The messages are
documentation-as-diagnostics; they match rule `82-failure-mode-ux.mdc`.

### 6.3 Forward compatibility

Adding new TOML fields is free: older binaries see unknown fields and
reject them only if the user manually adds a name the binary does
not know. On normal version-forward paths, the new field is added
first to the schema, a build with the new field is deployed, and only
then is the field written into any prefs file. This is the opposite
direction from typical "add field, old readers ignore" compatibility
stories: we **want** strict rejection so hand-edited malice is loud.

## 7. Threat model annotations

| Setting layer       | Tampered while locked? | Tampered while unlocked?           | Impact cap                         |
|---------------------|------------------------|------------------------------------|------------------------------------|
| Hardcoded constants | N/A (binary)           | Requires source modification       | Binary swap is out of scope        |
| TOML + HMAC         | Detected on next open  | Requires access to `file_kek` (= unlocked wallet) | UX degradation; bounded by §3.2 |
| CLI override        | Nothing to tamper      | Requires running `shekyl-cli` with attacker flags | Detected by `WARN` logs on open  |

A shell-config attacker who adds an alias wrapping `shekyl-cli` with
malicious flags is already past the wallet's threat model; the
open-time `WARN` lines still give the user a chance to notice.

## 8. Reference implementation pointer

- `shekyl_wallet_state::safety_constants::NetworkSafetyConstants` —
  §2.1 / §3.1 constants (`2k.1`). Landed in `shekyl-wallet-state`
  rather than `shekyl-consensus` because
  `70-modular-consensus.mdc` scopes the latter to PoW proof validation;
  per-network wallet safety policy is wallet-state concern.
- `shekyl_wallet_file::SafetyOverrides` — §2.3 runtime type (`2k.2`).
- `shekyl-wallet-prefs` crate — §2.2 TOML types, HMAC, parser (`2k.3`).
- `shekyl_ffi::wallet_prefs_ffi` — C ABI for the TOML layer (`2k.4`).
- `wallet2.cpp` rewire consuming the above — `2k.5`.

Each sub-commit must cite the section of this document it is
implementing. Reviewers should reject sub-commits that deviate from
the categorization without a corresponding amendment here.
