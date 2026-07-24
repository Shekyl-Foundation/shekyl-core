# shekyl-cli / simplewallet Parity Matrix

simplewallet registers **81** commands via `m_cmd_binder.set_handler`
(verified by `grep -c m_cmd_binder.set_handler src/simplewallet/simplewallet.cpp` on the current tree).

Phase 3 deletion gate: **every simplewallet command not in the explicit out-of-scope list has a tested equivalent in shekyl-cli, verified by this matrix.**

## Legend

- **Covered**: shekyl-cli has a working equivalent.
- **Out of scope**: Command is Monero-inherited dead code or irrelevant to Shekyl. Reason documented.
- **Planned**: Equivalent is designed but gated on an RPC surface that has not landed (RESERVED refusal in the CLI names the gate; carriers in `docs/FOLLOWUPS.md` §"WI-RPC-2b deferrals").

> **Note (2026-07-19, WI-RPC-1).** Rows 1–4's `account` / `--subaddr-index` /
> `address new` / `--subaddr-indices` language is **wallet2-era** and does not
> map to the Shekyl-native model: Shekyl has a single `ShekylAddress` with no
> subaddresses and no accounts. The Shekyl-native receive-attribution surface
> is the **payment request** — an opaque `rid` on the `shekyl:` URI — served
> by `shekyl-wallet-rpc` (`create_payment_request`, `list_payment_requests`,
> `make_uri`, `parse_uri`; contract in
> [`docs/api/wallet_rpc.yaml`](api/wallet_rpc.yaml)).

> **Note (2026-07-22, WI-RPC-2a/2b).** The migration the WI-RPC-1 note
> anticipated has landed. `shekyl-cli` is off wallet2 and is a JSON-RPC
> client of `shekyl-wallet-rpc` (Shape B — self-hosted in-process over a
> private UDS, or `--rpc-url`); the matrix below is reconciled against the
> WI-RPC-2b command set. The wallet2-era account/subaddress, key-image,
> secret-display, and sweep rows are closed **Out of scope
> (deleted-by-design)** — those commands refuse at parse time with guidance
> naming the Shekyl-native replacement (rule 60; WI-RPC-1 pin 1). Commands
> whose native surface is designed but not landed are **Planned** and answer
> with a RESERVED refusal naming their gate.
>
> **Update (2026-07-23, WI-RPC-2a review fixes).** For scripting/automation
> the CLI now also has non-interactive `create` / `restore` **subcommands**
> (`shekyl-cli create <name> --seed-out <path> [--password-file|--password-stdin]`;
> `restore <name> --seed-file <path> …`). The seed reaches a file **only**
> through the explicit `--seed-out` (0600, O_EXCL); the interactive `create`
> refuses to print the seed to a non-TTY (pipe/redirect/log) rather than leak
> it — so the `seed`-safety row's guarantee now holds on every path.

## Parity matrix (19 covered, 13 planned, 49 out of scope)

| # | simplewallet command | shekyl-cli equivalent | Status | Notes |
|---|---|---|---|---|
| 1 | `account` | N/A | Out of scope | Deleted-by-design (rule 60): no account model in Shekyl. Parse-time refusal points at payment requests |
| 2 | `address` | `address` | Covered | Single primary `ShekylAddress`; `address new` deleted — payment requests (`request new`) replace subaddress attribution |
| 3 | `balance` | `balance` | Covered | Native `get_balance`; `--account` flag deleted |
| 4 | `transfer` | `transfer` | Covered | Native build→confirm→submit/discard flow (`build_pending_tx`/`submit_pending_tx`/`discard_pending_tx`); `--subaddr-indices` deleted; `--do-not-relay` is Planned (row 26 workflow) |
| 5 | `show_transfers` | `transfers` | Covered | Native `get_transfers` |
| 6 | `show_transfer` | `show_transfer` | Covered | Native `get_transfer_by_txid` |
| 7 | `sweep_all` | N/A | Out of scope | Deleted-by-design: no Engine sweep surface; FOLLOWUPS "`sweep_all`" row carries the reopening criterion (Engine-level `build_sweep_tx`, specced contract-first) |
| 8 | `stake` | `stake` | Covered | Native `stake` RPC (WI-RPC-1 entry; Full-gated, resume-aware) |
| 9 | `unstake` | N/A | Planned | No native RPC surface yet; unbonding entry design pending (stake-lifecycle Phase 2b scope) |
| 10 | `claim_rewards` | N/A | Out of scope | No manual claim step by design: emission claims are assembled and dispatched engine-side (WI-2/WI-3 orchestration); rewards surface in `staked_balance` |
| 11 | `staking_info` | `staking_info` | Covered | Native `staking_info`, plus `staked_balance` / `staked_outputs` breakdowns (WI-RPC-1 reads) |
| 12 | `chain_health` | `chain_health` | Covered | Via independent DaemonClient |
| 13 | `seed` | N/A | Out of scope | Deleted-by-design: no secret-egress RPC. The mnemonic is shown once, at create/restore, under `display.rs` terminal safety |
| 14 | `viewkey` | N/A | Out of scope | Deleted-by-design: no secret-egress RPC |
| 15 | `spendkey` | N/A | Out of scope | Deleted-by-design: no secret-egress RPC |
| 16 | `export_key_images` | N/A | Out of scope | Deleted-by-design: Phase 2d `UnsignedTxBundle`/`SignedTxBundle` bundles replace the key-image workflow (locked) |
| 17 | `import_key_images` | N/A | Out of scope | Deleted-by-design: as row 16 |
| 18 | `get_tx_key` | N/A | Out of scope | Deleted-by-design (WI-RPC-3): raw per-tx-key export is REJECTED in the proofs contract (`docs/api/wallet_rpc.yaml` method registry) — the key is a bearer credential over the whole tx; refuses at parse time pointing at `get_tx_proof`/`check_tx_proof` |
| 19 | `check_tx_key` | N/A | Out of scope | As row 18 |
| 20 | `get_tx_proof` | `get_tx_proof` | Covered | Native DLEQ tx proof, direction auto-selected (OUTBOUND/INBOUND) by decoded-address comparison (WI-RPC-3); prints the contract's disclosure warnings at generation |
| 21 | `check_tx_proof` | `check_tx_proof` | Covered | Wallet-less verification against the chain (WI-RPC-3); proof strings are kept out of readline history |
| 22 | `get_reserve_proof` | `get_reserve_proof` | Covered | All-balance or amount-bounded (WI-RPC-3, FULL wallet); prints the key-image-beacon warning |
| 23 | `check_reserve_proof` | `check_reserve_proof` | Covered | Wallet-less verification with daemon spent-status reporting (WI-RPC-3) |
| 24 | `sign` | RESERVED | Planned | Gated on the message-signing RPC surface (Phase 2c) |
| 25 | `verify` | RESERVED | Planned | As row 24 |
| 26 | `sign_transfer` | RESERVED | Planned | Gated on the Phase 2d offline cold-signing workflow (with `describe_transfer`, `submit_transfer`, `transfer --do-not-relay`) |
| 27 | `submit_transfer` | RESERVED | Planned | As row 26 |
| 28 | `password` | `password` | Covered | Native `change_password` flow, old-first |
| 29 | `rescan_bc` | RESERVED | Planned | `rescan_blockchain` is contract-`SPECIFIED`, returns `-32601` pending the Engine rescan API (FOLLOWUPS Phase 4b row) |
| 30 | `refresh` | `refresh` | Covered | Native `refresh` |
| 31 | `save` | `save` | Covered | Informative: state persists crash-atomically after every operation; nothing to save |
| 32 | `status` | `status` | Covered | Native wallet + daemon sync heights |
| 33 | `wallet_info` | RESERVED (`engine_info`) | Planned | Gated on a native wallet-info RPC method |
| 34 | `version` | `version` | Covered | CLI version + `get_version` from the connected server |
| 35 | `help` | `help` | Covered | Categorized; names the RESERVED set and its gates |
| 36 | `bc_height` | `status` | Covered | Height shown in status |
| 37 | `fee` | `fee` | Covered | Native `get_default_fee_priority` tier quotes + `estimate_tx_size_and_weight` (WI-RPC-1). Principal lane only — P-lane fees are canonical, never user-facing |
| 38 | `set_daemon` | `--daemon-address` | Covered | CLI flag, not runtime change; `--rpc-url` selects an external wallet-RPC |
| 39 | `incoming_transfers` | `transfers` | Covered | `transfers` shows all directions; the unattributed-receives view (`history incoming`) is RESERVED on the FA-8 projection |
| 40 | `restore_height` | `restore` | Covered | Native `restore_wallet` (BIP-39 + optional `restore_height`) |
| 41 | `address_book` | N/A | Out of scope | Monero feature, not used in Shekyl |
| 42 | `apropos` | N/A | Out of scope | Help search, low value |
| 43 | `donate` | N/A | Out of scope | Monero donation address |
| 44 | `encrypted_seed` | N/A | Out of scope | Encrypted seed export not needed with display.rs safety |
| 45 | `export_outputs` | N/A | Out of scope | Output export for multisig, not supported |
| 46 | `export_transfers` | N/A | Out of scope | CSV export, low priority |
| 47 | `freeze` | N/A | Out of scope | Output freezing, Monero-specific feature |
| 48 | `frozen` | N/A | Out of scope | List frozen outputs |
| 49 | `get_description` | N/A | Out of scope | Wallet description, trivial metadata |
| 50 | `get_tx_note` | N/A | Out of scope | Transaction notes, trivial metadata |
| 51 | `hw_key_images_sync` | N/A | Out of scope | Hardware wallet, not supported |
| 52 | `hw_reconnect` | N/A | Out of scope | Hardware wallet, not supported |
| 53 | `import_outputs` | N/A | Out of scope | Output import for multisig, not supported |
| 54 | `integrated_address` | N/A | Out of scope | Shekyl uses different addressing |
| 55 | `lock` | N/A | Out of scope | Wallet locking, low priority |
| 56 | `net_stats` | N/A | Out of scope | Network stats, daemon concern |
| 57 | `payment_id` | N/A | Out of scope | Payment IDs deprecated |
| 58 | `payments` | N/A | Out of scope | Payment ID lookup, deprecated |
| 59 | `public_nodes` | N/A | Out of scope | Public node discovery, daemon concern |
| 60 | `rescan_spent` | N/A | Out of scope | Spent output rescan; folds into the row-29 rescan surface when it lands |
| 61 | `rpc_payment_info` | N/A | Out of scope | RPC payment, Monero feature removed |
| 62 | `save_bc` | N/A | Out of scope | Blockchain save, daemon concern |
| 63 | `save_watch_only` | N/A | Out of scope | Watch-only export, future follow-up |
| 64 | `scan_tx` | N/A | Out of scope | Single-tx scan, low priority |
| 65 | `set` | N/A | Out of scope | Runtime settings, replaced by CLI flags |
| 66 | `set_description` | N/A | Out of scope | Wallet description, trivial metadata |
| 67 | `set_log` | N/A | Out of scope | Log level, use RUST_LOG env var |
| 68 | `set_tx_key` | N/A | Out of scope | Manual tx key injection, niche |
| 69 | `set_tx_note` | N/A | Out of scope | Transaction notes, trivial metadata |
| 70 | `show_qr_code` | N/A | Out of scope | QR display, GUI concern |
| 71 | `start_mining` | N/A | Out of scope | Mining, daemon concern |
| 72 | `start_mining_for_rpc` | N/A | Out of scope | RPC mining, removed |
| 73 | `stop_mining` | N/A | Out of scope | Mining, daemon concern |
| 74 | `stop_mining_for_rpc` | N/A | Out of scope | RPC mining, removed |
| 75 | `sweep_account` | N/A | Out of scope | Sweep deleted with row 7; no account model regardless |
| 76 | `sweep_below` | N/A | Out of scope | Dust sweeping, niche |
| 77 | `sweep_single` | N/A | Out of scope | Single output sweep, niche |
| 78 | `sweep_unmixable` | N/A | Out of scope | Monero mixin rules, not applicable |
| 79 | `thaw` | N/A | Out of scope | Unfreeze outputs, not supported |
| 80 | `unspent_outputs` | N/A | Out of scope | UTXO listing, low priority |
| 81 | `welcome` | N/A | Out of scope | Interactive tutorial, replaced by help |
