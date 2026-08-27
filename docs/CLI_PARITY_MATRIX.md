# shekyl-cli / simplewallet Parity Matrix

simplewallet registered **81** commands via `m_cmd_binder.set_handler`.

**This matrix is a capability ledger, not a gate.** It was written as the
Phase 3 deletion gate, and that gate is discharged: `src/simplewallet/` was
deleted at `a36224bde`, so its verification recipe (`grep -c
m_cmd_binder.set_handler src/simplewallet/simplewallet.cpp`) no longer
resolves and the count above is historical. What the matrix tracks now is
which capabilities `shekyl-cli` carries — so a **Planned** row is an open
capability, never a blocker on deleting C++ that no longer exists.

## Legend

- **Covered**: shekyl-cli has a working equivalent.
- **Out of scope**: Command is Monero-inherited dead code or irrelevant to Shekyl. Reason documented.
- **Planned**: Equivalent is designed but not yet built in `shekyl-cli`. Usually that is because the RPC surface it needs has not landed (RESERVED refusal in the CLI names the gate; carriers in `docs/FOLLOWUPS.md` §"WI-RPC-2b deferrals"). Where the RPC *has* landed and only the CLI command is outstanding, the row's note says so — those are unblocked, not gated.

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

## Parity matrix (29 covered, 1 planned, 2 rejected, 49 out of scope)

| # | simplewallet command | shekyl-cli equivalent | Status | Notes |
|---|---|---|---|---|
| 1 | `account` | N/A | Out of scope | Deleted-by-design (rule 60): no account model in Shekyl. Parse-time refusal points at payment requests |
| 2 | `address` | `address` | Covered | Single primary `ShekylAddress`; `address new` deleted — payment requests (`request new`) replace subaddress attribution |
| 3 | `balance` | `balance` | Covered | Native `get_balance`; `--account` flag deleted |
| 4 | `transfer` | `transfer` | Covered | Native build→confirm→submit/discard flow (`build_pending_tx`/`submit_pending_tx`/`discard_pending_tx`); `--subaddr-indices` deleted; `--do-not-relay` is Planned (row 26 workflow) |
| 5 | `show_transfers` | `transfers` | Covered | Native `get_transfers` |
| 6 | `show_transfer` | `show_transfer` | Covered | Native `get_transfer_by_txid` |
| 7 | `sweep_all` | N/A | Out of scope | Deleted-by-design: no Engine sweep surface; FOLLOWUPS "`sweep_all`" row carries the reopening criterion (Engine-level `build_sweep_tx`, specced contract-first) |
| 8 | `stake` | `stake` | Covered | Native `stake` RPC (WI-RPC-1 entry; Full-gated, resume-aware). Posture-aware: no flag ⇒ `posture: "market"` (today `-29505`, shard assignment unbuilt) |
| 8a | `stake --complete-tree-foundation` | `stake` + `posture: "foundation_complete_tree"` + `acknowledge_non_earning_unbounded: true` | Covered | Foundation whole-corpus posture (COMPLETETREE_ACTIVATION D-2/D-4). CLI prints the terms verbatim and requires the typed phrase `serve without reward`; the RPC refuses `-29506` without the acknowledgment, and that refusal's body **is** the warning. Deliberately CLI-only by convention — the GUI never sends the field |
| 9 | `unstake` | N/A | Planned | No native RPC surface yet — but **no longer "design pending"** (corrected 2026-08-26, PR-P4). The producer is built: `build_unbond_vin` for the witness and `AssembleUnbond` for the full persona-bound exit transaction, with the surface-A auth slot under `bond_spend_pk`. Remaining gates: **reachability** (no RPC/CLI until the regtest walk), **dispatch** of the assembled bytes, and **native `/submit_transaction` admission** — the JoinMarket-only battery still refuses Unbond as `Malformed`; the construction-leg reopen has fired, the Unbond submit fact set has not. Reopen criterion lives in `api/wallet_rpc.yaml`'s RESERVED `unstake` entry |
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
| 22 | `get_reserve_proof` | `get_reserve_proof` | Covered | All-balance or amount-bounded (WI-RPC-3, FULL wallet). Grammar is `get_reserve_proof [amount] [message...]`: an amount-shaped first token binds as the bound, so the CLI echoes the bound amount and exact challenge message at generation; flag-shaped tokens (e.g. Monero's `--all`) are refused with a usage error rather than bound into the message. Prints the key-image-beacon warning |
| 23 | `check_reserve_proof` | `check_reserve_proof` | Covered | Wallet-less verification with daemon spent-status reporting (WI-RPC-3) |
| 24 | `sign` | `sign` | Covered | Native `sign_message` (PR-SM-2): the ratified nested hybrid (SLH-DSA-192s inner / spend-Schnorr outer, [`WALLET_MESSAGE_SIGNING.md`](design/WALLET_MESSAGE_SIGNING.md) §7). Multi-second by design (~4 s floor); the CLI prints the expectation before the call |
| 25 | `verify` | `verify` | Covered | Native `verify_message` (PR-SM-2), **session-less** — works with no wallet open (SM-R-6). Signature pastes are kept out of readline history; `@path` reads a file so a mail-wrapped 21.7 KB line does not have to survive the REPL tokenizer. Live end to end since the fork-(ii) address layout landed (2026-08-15): every address carries the 48-byte signing anchor |
| 26 | `sign_transfer` | RESERVED | Rejected (V3.0) | A4 (2026-08-06) descoped air-gapped cold bundles from V3.0: V3.0 ships cold *storage*, not cold *signing*. Not a pending gate — `export_unsigned`/`submit_signed` are REJECTED in [`wallet_rpc.yaml`](api/wallet_rpc.yaml). **Rule-21 reopen:** a concrete offline-signing workflow, landed as `UnsignedTxBundle`/`SignedTxBundle`, never as a wallet2-era binary format. See [`FOLLOWUPS.md`](FOLLOWUPS.md) A4 |
| 27 | `submit_transfer` | RESERVED | Rejected (V3.0) | As row 26 |
| 28 | `password` | `password` | Covered | Native `change_password` flow, old-first |
| 29 | `rescan_bc` | `rescan` | Covered | Native `rescan_blockchain` via `Engine::start_rescan` (Phase 4c). `hard` is accepted for wallet2 muscle memory and reported as equivalent — Shekyl has one rescan, which already rebuilds every scan-derived fact |
| 30 | `refresh` | `refresh` | Covered | Native `refresh` |
| 31 | `save` | `save` | Covered | Informative: state persists crash-atomically after every operation; nothing to save |
| 32 | `status` | `status` | Covered | Native wallet + daemon sync heights |
| 33 | `wallet_info` | `engine_info` | Covered | Native `get_wallet_info` aggregate (WI-RPC-4) |
| 34 | `version` | `version` | Covered | CLI version + `get_version` from the connected server |
| 35 | `help` | `help` | Covered | Categorized; names the RESERVED set and its gates |
| 36 | `bc_height` | `status` | Covered | Height shown in status |
| 37 | `fee` | `fee` | Covered | Native `get_default_fee_priority` tier quotes + `estimate_tx_size_and_weight` (WI-RPC-1). Principal lane only — P-lane fees are canonical, never user-facing |
| 38 | `set_daemon` | `--daemon-address` | Covered | CLI flag, not runtime change; `--rpc-url` selects an external wallet-RPC |
| 39 | `incoming_transfers` | `transfers` / `history incoming --unattributed` | Covered | `transfers` lists ledger rows; unattributed receives via `get_transfers` attribution filter (WI-RPC-4) |
| 40 | `restore_height` | `restore` | Covered | Native `restore_wallet` (BIP-39 + optional `restore_height`) |
| 41 | `address_book` | N/A | Out of scope | Monero feature, not used in Shekyl |
| 42 | `apropos` | N/A | Out of scope | Help search, low value |
| 43 | `donate` | N/A | Out of scope | Monero donation address |
| 44 | `encrypted_seed` | N/A | Out of scope | Encrypted seed export not needed with display.rs safety |
| 45 | `export_outputs` | N/A | Out of scope | Removed by construction: the cold-coordination flow it served is descoped by A4, and FCMP++ membership proofs need no per-wallet output export |
| 46 | `export_transfers` | N/A | Out of scope | CSV export, low priority |
| 47 | `freeze` | N/A | Out of scope | Removed by construction (rule 60): freezing exists to keep a poisoned decoy out of a ring. FCMP++ has no decoy selection, so the hazard has no referent |
| 48 | `frozen` | N/A | Out of scope | As row 47 — nothing can be frozen |
| 49 | `get_description` | N/A | Out of scope | Wallet description, trivial metadata |
| 50 | `get_tx_note` | `get_tx_note` | Covered | Native `get_tx_note` (PR-SA-4 / SJ-DQ-7); CLI landed WI-RPC-5. An absent note is also the answer for an unknown txid — the note store carries no existence claim |
| 51 | `hw_key_images_sync` | N/A | Out of scope | Hardware wallet, not supported |
| 52 | `hw_reconnect` | N/A | Out of scope | Hardware wallet, not supported |
| 53 | `import_outputs` | N/A | Out of scope | As row 45 |
| 54 | `integrated_address` | N/A | Out of scope | Shekyl uses different addressing |
| 55 | `lock` | N/A | Out of scope | Wallet locking, low priority |
| 56 | `net_stats` | N/A | Out of scope | Network stats, daemon concern |
| 57 | `payment_id` | N/A | Out of scope | Payment IDs deprecated |
| 58 | `payments` | N/A | Out of scope | Payment ID lookup, deprecated |
| 59 | `public_nodes` | N/A | Deleted | Daemon `/get_public_nodes` removed (operator-to-operator RPC; `docs/DAEMON_RPC_RUST.md`) |
| 60 | `rescan_spent` | N/A | Out of scope | Spent output rescan; folds into the row-29 rescan surface when it lands |
| 61 | `rpc_payment_info` | N/A | Out of scope | RPC payment, Monero feature removed |
| 62 | `save_bc` | N/A | Out of scope | Blockchain save, daemon concern |
| 63 | `save_watch_only` | N/A | Out of scope | Watch-only export, future follow-up |
| 64 | `scan_tx` | N/A | Out of scope | Single-tx scan, low priority |
| 65 | `set` | N/A | Out of scope | Runtime settings, replaced by CLI flags |
| 66 | `set_description` | N/A | Out of scope | Wallet description, trivial metadata |
| 67 | `set_log` | N/A | Out of scope | Log level, use RUST_LOG env var |
| 68 | `set_tx_key` | N/A | Out of scope | Manual tx key injection, niche |
| 69 | `set_tx_note` | `set_tx_note` | Covered | Native `set_tx_note` (PR-SA-4 / SJ-DQ-7); CLI landed WI-RPC-5. The note is the verbatim line remainder; a missing note is a usage error, never a silent clear (the wire's empty-note clear stays RPC-only). 4096-UTF-8-byte ceiling |
| 70 | `show_qr_code` | N/A | Out of scope | QR display, GUI concern |
| 71 | `start_mining` | N/A | Out of scope | Mining, daemon concern |
| 72 | `start_mining_for_rpc` | N/A | Out of scope | RPC mining, removed |
| 73 | `stop_mining` | N/A | Out of scope | Mining, daemon concern |
| 74 | `stop_mining_for_rpc` | N/A | Out of scope | RPC mining, removed |
| 75 | `sweep_account` | N/A | Out of scope | Sweep deleted with row 7; no account model regardless |
| 76 | `sweep_below` | N/A | Out of scope | Dust sweeping, niche |
| 77 | `sweep_single` | N/A | Out of scope | Single output sweep, niche |
| 78 | `sweep_unmixable` | N/A | Out of scope | Monero mixin rules, not applicable |
| 79 | `thaw` | N/A | Out of scope | As row 47 |
| 80 | `unspent_outputs` | N/A | Out of scope | UTXO listing, low priority |
| 81 | `welcome` | N/A | Out of scope | Interactive tutorial, replaced by help |

## Shekyl-native commands with no simplewallet ancestor

Capabilities `shekyl-cli` carries that the wallet2-era CLI never had. Same
legend; numbered `S<n>` so the 81 historical rows stay stable.

| # | shekyl-cli command | RPC method | Status | Notes |
|---|---|---|---|---|
| S1 | `request new` / `requests list` / `make_uri` / `parse_uri` | `create_payment_request` etc. | Covered | The payment-request receive-attribution surface (WI-RPC-1); replaces accounts/subaddresses per the 2026-07-19 note above |
| S2 | `abandon <txid>` | `abandon_tx` | Covered | Give up on a dispatched send (PR-SJ-3); CLI landed WI-RPC-5. The copy states that input locks stay held until confirmed-absent evidence releases them, and a late confirmation flips the row back to CONFIRMED |
| S3 | `stake_in <amount>` | `stake_in` | Covered | Fund the staking balance with an ordinary principal transfer (WI-RPC-5). Amount-only grammar — cover is system-drawn, no `P` address on the wire. Prints the GF-7 change-co-presence disclosure before confirming (residual carried in [`FOLLOWUPS.md`](FOLLOWUPS.md)) |
| S4 | `drain_balance` | `get_drain_balance` | Covered | Aggregate drainable staking amount (WI-RPC-5); two-armed — while syncing it says so and never prints a zero that would lie (rule 82 / F-D2) |
| S5 | `drain <amount>` | `drain` | Covered | Move staking funds back to this wallet (WI-RPC-5). No fee/destination/slot grammar exists, by contract: fee is the canonical P-lane floor, destination is engine-pinned to this wallet (T-DS-3); flag-shaped tokens are refused at parse |
