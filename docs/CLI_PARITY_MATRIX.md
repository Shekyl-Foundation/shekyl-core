# shekyl-cli / simplewallet Parity Matrix

simplewallet registers **81** commands via `m_cmd_binder.set_handler`
(verified by `grep -c m_cmd_binder.set_handler src/simplewallet/simplewallet.cpp` on the current tree).

Phase 3 deletion gate: **every simplewallet command not in the explicit out-of-scope list has a tested equivalent in shekyl-cli, verified by this matrix.**

## Legend

- **Covered**: shekyl-cli has a working equivalent.
- **Out of scope**: Command is Monero-inherited dead code or irrelevant to Shekyl. Reason documented.
- **Planned**: Equivalent exists but needs testing or minor work.

## Parity matrix (40 covered, 41 out of scope)

| # | simplewallet command | shekyl-cli equivalent | Status | Notes |
|---|---|---|---|---|
| 1 | `account` | `account show/default/new` | Covered | Session-default model, no "switch" |
| 2 | `address` | `address` | Covered | With `--subaddr-index`, `address new` |
| 3 | `balance` | `balance` | Covered | With `--account N` |
| 4 | `transfer` | `transfer` | Covered | `--do-not-relay`, `--no-confirm`, `--subaddr-indices` |
| 5 | `show_transfers` | `transfers` | Covered | Renamed for brevity |
| 6 | `show_transfer` | `show_transfer` | Covered | |
| 7 | `sweep_all` | `sweep_all` | Covered | Privacy warning + confirm_dangerous |
| 8 | `stake` | `stake` | Covered | With tier display + confirmation |
| 9 | `unstake` | `unstake` | Covered | |
| 10 | `claim_rewards` | `claim` | Covered | Shortened name |
| 11 | `staking_info` | `staking_info` | Covered | |
| 12 | `chain_health` | `chain_health` | Covered | Via independent DaemonClient |
| 13 | `seed` | `seed` | Covered | Terminal safety, display.rs |
| 14 | `viewkey` | `viewkey` | Covered | Terminal safety, display.rs |
| 15 | `spendkey` | `spendkey` | Covered | Terminal safety, confirm_dangerous |
| 16 | `export_key_images` | `export_key_images` | Covered | 0600 permissions, `--since-height`, `--all` |
| 17 | `import_key_images` | `import_key_images` | Covered | Format validation |
| 18 | `get_tx_key` | `get_tx_key` | Covered | |
| 19 | `check_tx_key` | `check_tx_key` | Covered | |
| 20 | `get_tx_proof` | `get_tx_proof` | Covered | |
| 21 | `check_tx_proof` | `check_tx_proof` | Covered | |
| 22 | `get_reserve_proof` | `get_reserve_proof` | Covered | |
| 23 | `check_reserve_proof` | `check_reserve_proof` | Covered | |
| 24 | `sign` | `sign` | Covered | Domain separation documented |
| 25 | `verify` | `verify` | Covered | |
| 26 | `sign_transfer` | `sign_transfer` | Covered | Cold-signing workflow |
| 27 | `submit_transfer` | `submit_transfer` | Covered | |
| 28 | `password` | `password` | Covered | Old-first with fast-fail validation |
| 29 | `rescan_bc` | `rescan [hard]` | Covered | confirm_dangerous for hard |
| 30 | `refresh` | `refresh` | Covered | |
| 31 | `save` | `save` | Covered | |
| 32 | `status` | `status` | Covered | |
| 33 | `wallet_info` | `wallet_info` | Covered | No filename shown |
| 34 | `version` | `version` | Covered | |
| 35 | `help` | `help` | Covered | Categorized |
| 36 | `bc_height` | `status` | Covered | Height shown in status |
| 37 | `fee` | N/A | Covered | Fee shown in transfer output |
| 38 | `set_daemon` | `--daemon-address` | Covered | CLI flag, not runtime change |
| 39 | `incoming_transfers` | `transfers` | Covered | `transfers` shows all directions |
| 40 | `restore_height` | `restore` | Covered | Restore height prompted during restore |
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
| 60 | `rescan_spent` | N/A | Out of scope | Spent output rescan, covered by `rescan hard` |
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
| 75 | `sweep_account` | `sweep_all --account N` | Out of scope | Covered by sweep_all with --account |
| 76 | `sweep_below` | N/A | Out of scope | Dust sweeping, niche |
| 77 | `sweep_single` | N/A | Out of scope | Single output sweep, niche |
| 78 | `sweep_unmixable` | N/A | Out of scope | Monero mixin rules, not applicable |
| 79 | `thaw` | N/A | Out of scope | Unfreeze outputs, not supported |
| 80 | `unspent_outputs` | N/A | Out of scope | UTXO listing, low priority |
| 81 | `welcome` | N/A | Out of scope | Interactive tutorial, replaced by help |
