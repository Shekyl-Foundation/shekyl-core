# Where a Wallet Setting Lives

**Status:** LIVING CONTRACT, last verified 2026-11-21.
**Scope:** every setting a Shekyl wallet acts on, and the one place each
lives. A wallet carries no preferences file: the plaintext-with-HMAC
`<base>.prefs.toml` and its `shekyl-engine-prefs` crate were deleted
(Rick, 2026-11-21; [`V3_WALLET_DECISION_LOG.md`](./V3_WALLET_DECISION_LOG.md)
2026-11-21). The policy that defined that file is
[`completed/WALLET_PREFS.md`](./completed/WALLET_PREFS.md).
**Related:** [WALLET_FILE_FORMAT_V1.md](./WALLET_FILE_FORMAT_V1.md) ·
[`142-serialization-policy.mdc`](../.cursor/rules/142-serialization-policy.mdc) ·
[`design/INPUT_GRAMMAR.md`](./design/INPUT_GRAMMAR.md) §12.

## 1. The decision order

A new wallet setting is placed by asking, in this order. The funds question
comes first, before "is it user-tunable?":

1. **Does resetting it to its default lose or endanger funds?** → **Sealed
   wallet state** (§5). Stop. `staking_enabled`, `p_slot` and the bonded set
   are user-chosen *and* funds-load-bearing, so they are sealed state.
2. **Is it network-fixed, with no legitimate per-wallet variance?** →
   **Hardcoded** (§2), with a session override (§3) where a session may need
   to deviate.
3. **Is it a property of the machine running the wallet?** → **An option of
   that process** (§4): given each time the process starts, never stored with
   a wallet, because a wallet moves between machines and the machine's answer
   does not.
4. **Is it how a front end shows or behaves?** → **The front end's own
   configuration.** No front-end setting is stored with a wallet.

There is no fifth place. A setting a wallet carries with it is sealed state;
there is no advisory per-wallet settings file to reset, tamper or tear.

## 2. Hardcoded constants

Baked into the binary. Users cannot change these through any normal workflow.

- **Principle:** any tampering with these values threatens funds (a wallet that
  accepts a reorg it should reject, reuses view secrets across transactions, or
  silently skips scanning).
- **Storage:** the one constant set
  `shekyl_engine_state::safety_constants::WalletSafetyConstants::DEFAULTS`, the
  same on every network (`NETWORK_IDENTITY.md` NI-R4; Rick, 2026-11-03).
- **Why not an override for all of them:** "always on" is safer than "on by
  default, the user can disable". For a field with no legitimate reason to
  deviate, removing the knob removes the attack surface.

Fields marked **invariant** admit no override; fields marked **base** supply the
default the session override of §3 overlays at open.

| Field                              | Value   | Kind      | Rationale |
|------------------------------------|---------|-----------|-----------|
| `key_reuse_mitigation2`            | `true`  | invariant | Defense against view-key-reuse linkability; always on. |
| `max_reorg_depth`                  | `10`    | base      | Minimum confirmations before a transfer is final: `shekyl_consensus::DEFAULT_LOCK_WINDOW`, referenced, not restated. An output cannot be spent until that many blocks have passed, so a wallet treating a transfer as final sooner would report finality the chain does not grant. Override (raise only): §3. |
| `default_skip_to_height`           | `0`     | base      | One-shot import hint (starting height for the first scan). Override: §3. Once a `SyncStateBlock` exists its stored `restore_from_height` supersedes this default. |
| `default_refresh_from_block_height`| `0`     | base      | Refresh cursor used when the wallet opens without a `SyncStateBlock` (lost-`.wallet` recovery path). Override: §3. |

`segregation_pre_fork_outputs` and `segregation_height` (Monero's
post-key-reuse-mitigation fork segregation) are deliberately absent: no
pre-fork output set exists for a Shekyl wallet (rule 60).

## 3. Session overrides

The mechanism for a session to deviate from a **base** constant (§2):
`shekyl_engine_file::SafetyOverrides`, passed by value into
`WalletFile::open`; `Debug` but not `Serialize`, so it is never persisted, and
every active override emits a `WARN` line at open naming the field, its value
and the default. The absence of storage is the defense against
attacker-seeded overrides.

The fields it can carry:

| Field                        | Default                 | Rule |
|------------------------------|-------------------------|------|
| `max_reorg_depth`            | `10` (the lock window)  | Raise only. `ReorgDepthOverride::new` refuses a depth below the lock window with its reason (`ReorgDepthBelowLockWindow`): a shallower depth means nothing the chain respects. |
| `skip_to_height`             | `0`                     | One-shot bootstrap parameter; after the first scan `SyncStateBlock.restore_from_height` takes over. |
| `refresh_from_block_height`  | `0`                     | One-shot import hint, as `skip_to_height`. |

**No binary offers an override today.** Every host (`shekyl-wallet-rpc`, the
CLI's in-process server, the GUI) passes `SafetyOverrides::none()`, and no
binary's table in [`design/INPUT_GRAMMAR.md`](./design/INPUT_GRAMMAR.md) §12
has an override row.

## 4. Options of the process that runs the wallet

What only the machine knows: an option of the binary that hosts the wallet,
given at every start, never stored with a wallet. Its name is in that binary's
table ([`design/INPUT_GRAMMAR.md`](./design/INPUT_GRAMMAR.md) §12.1, §12.4).

| Option     | Binaries                                        | Default | Behaviour |
|------------|-------------------------------------------------|---------|-----------|
| `tor-file` | `shekyl-wallet-rpc`; `shekyl-cli` for its own in-process server (refused with `wallet-rpc-endpoint` or `wallet-rpc-socket-file`) | unset: discovery (`tor/tor` beside the executable, else the version-exact bundle directory under `/opt/shekyl/` on Unix) | The Tor binary a serving wallet runs, with the daemon's behaviour (IG-Q41). Resolved once at start (`shekyl_engine_core::TorFile`): a relative path refuses the start before it is looked for, since a `path` is absolute (IG-6) and serving restarts its supervisor from wherever the process then stands; a path naming no file on this machine refuses the start with its remedy; a path naming a file is taken and must still pass the pin. Neither is ever replaced by discovery. The GUI starts no serving host, so it has no such option. |

## 5. Sealed wallet state

Funds-load-bearing state the engine reconciles against the chain: the output
set, key images, the sync cursor, the send journal, and the staking persona
(`staking_enabled`, the monotone slot cursor, the reconcilable live-bond hint).
Not user-edited; a reset to default would lose or endanger funds.

- **Principle:** losing or tampering with this state loses or endangers funds,
  so it is never silently defaulted: it **refuses to load** on any drift.
- **Storage:** `shekyl_engine_state` blocks (`WalletLedger` and its inner blocks,
  including `StakingBlock`) in file-layout region 2 of the `.wallet` file,
  AEAD-sealed (XChaCha20-Poly1305) under the region-2 wrap key derived from
  `file_kek` ([WALLET_FILE_FORMAT_V1.md](./WALLET_FILE_FORMAT_V1.md)).
- **Integrity and evolution:** strict per-block version constants,
  snapshot-pinned and CI-enforced by
  [`142-serialization-policy.mdc`](../.cursor/rules/142-serialization-policy.mdc);
  a version mismatch refuses rather than migrates.

## 6. Settings with no place

The settings Monero's `wallet2` carried that have no place in a Shekyl wallet,
each with its reason. None is read anywhere.

### 6.1 REJECTED: the coin-selection knobs (Rick, 2026-11-21)

`min_output_count`, `min_output_value`, `ignore_outputs_above`,
`ignore_outputs_below` and `merge_destinations` are REJECTED, for the reason
given for the user freeze (2026-11-15): a human choice on a visible transaction
parameter becomes a pattern, while deterministic selection gives every wallet
the same shapes. `shekyl-cli` refuses each by name with that reason; its command table (`design/INPUT_GRAMMAR.md` §12.3) is the only place they are recorded, since the wallet contract never exposed these names. They reopen
only on a named user job the wallet's own selection does not cover.

### 6.2 Deleted

| Setting | Reason |
|---|---|
| `tor_binary_path` | Machine-scoped; it is the `tor-file` option (§4). |
| `default_decimal_point` | A front end's display; no front end reads a stored unit. |
| `show_wallet_name_when_locked` | No front end has a locked state. |
| `inactivity_lock_timeout` | No front end locks a session after inactivity; nothing read it. |
| `setup_background_mining` | Monero's background-mining prompt; a Shekyl wallet does not mine. |
| `confirm_backlog`, `confirm_backlog_threshold` | Monero's pool-backlog warning; nothing read them. |
| `confirm_export_overwrite`, `export_format` | No export reads them. |
| `always_confirm_transfers` | `shekyl-cli` always shows a built transfer and waits for confirmation; not a setting. |
| `refresh_type` | Monero's refresh modes; the scanner has one. |
| `auto_refresh` | Nothing read it. |
| `auto_low_priority` | The fee is chosen per send; nothing read it. |
| `track_uses` | Monero's ring-member use tracking; FCMP++ has no rings. |
| `store_tx_info` | Send records are sealed state (the send journal), always kept. |
| `device_name`, `device_derivation_path` | Nothing read them; device selection, if built, is per-machine configuration. |
| `seed_language` | The seed is BIP-39 English ([V3_WALLET_DECISION_LOG.md](./V3_WALLET_DECISION_LOG.md), the per-network seed policy); there is no language to choose. |
| `schema_version` | The deleted file's own version. |

### 6.3 Dropped with the envelope

| Field                    | Disposition |
|--------------------------|-------------|
| `encrypted_secret_keys`  | The envelope itself is AEAD-encrypted; the marker is meaningless. |
| `original_keys_available`| Superseded by the capability mode byte; `FULL` is the only live mode (view-only REJECTED, decision log 2026-09-07). |
| `watch_only`             | REJECTED with the view-only capability (decision log 2026-09-07). |
| `background_sync_type`   | Not V3.0 scope. |
| `nettype`                | Wallet identity, committed in the `.wallet.keys` AAD. |

No migration from `wallet2` blobs: Shekyl wallets are created fresh. A
`<base>.prefs.toml` / `.prefs.toml.hmac` pair an earlier build left beside a
wallet is not read, not moved and not deleted.
