# Wallet → Engine rename: pre-commit grep audit

Date: 2026-04-27
Branch: `chore/wallet-to-engine-rename`
Commit context: documents the residual `wallet` / `Wallet` /
`WALLET` references that remain after the mechanical Wallet → Engine
rename, with each residual classified as one of:

(a) **Domain primitive** — `wallet` is the user-of-secrets domain
    concept, *not* the orchestrator. Examples: file format primitives
    (`WalletFile`, `WalletLedger`, `WalletPrefs`,
    `WalletEnvelopeError`, `WalletOutput`), the
    `shekyl-crypto-pq::wallet_envelope` and
    `shekyl-crypto-pq::wallet_state` modules (crypto-side identity
    material, not orchestrator state), the `wallet_ledger` /
    `wallet_envelope` / `wallet_envelope_ffi` source filenames.
    These survive the rename on purpose; renaming them would either
    weaken the file format vocabulary or pre-empt a separate
    primitives audit.

(b) **File extension** — the on-disk file extension `.wallet` and
    `.wallet.keys` is intentionally retained. Existing tooling and
    [`docs/WALLET_FILE_FORMAT_V1.md`](../WALLET_FILE_FORMAT_V1.md)
    describe this contract; changing the extension is out of scope
    for the rename. The default home directory subtree
    `~/.shekyl/wallets/` does change to `~/.shekyl/engines/` but
    the file extensions inside that subtree do not.

(c) **Deferred FFI / C++ surface** — `shekyl_wallet_*` `#[no_mangle]`
    C ABI exports, the `ShekylWallet` opaque-handle struct, the
    C++ `Wallet2` binding referenced from `shekyl-engine-rpc::ffi`
    and `shekyl-cli/src/engine.rs`, and the C++ JSON-RPC method names
    (`wallet_get_balance`, `change_wallet_password`, ...) carried as
    string literals in handler dispatch. These rename in V3.2 paired
    with `wallet2.cpp` retirement (FFI symbols) and Phase 4b
    Shekyl-native RPC method-set work (JSON-RPC names). See
    [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) "V3.2 — Rust cutover and
    cleanup" for the deferred-work entries.

(d) **Historical decision-log / CHANGELOG entry** — entries in
    `docs/V3_WALLET_DECISION_LOG.md` and shipped CHANGELOG sections
    (`[3.1.0-alpha.5]`, `[3.1.0-alpha.3]`, `[3.1.0-alpha.2]`,
    `[3.1.0-alpha.1]`, `[core-v3.1.0]`, `[3.0.3-RC1]`) describe
    historical state. Per `90-commits.mdc` and the rename plan,
    history is not edited; the only permitted edit is a forward-
    pointer on the `RwLock<Wallet>` decision log entry that links to
    the `2026-04-27` actor-architecture entry.

(e) **Prose / domain-noun residual** — English prose mentioning
    "wallet" as a generic user-money word ("Wallet state management",
    "the wallet's transaction history", "wallet-internal feature").
    These read correctly because "wallet" is the user-facing domain
    noun for a set of secrets. The Rust-side orchestrator type is
    `Engine`; the user concept the orchestrator serves is still
    a wallet. User-facing CLI strings have been switched to "engine"
    per Option α; in-code prose follows behind without breaking
    user-of-secrets vocabulary.

## Counts

After the rename, in tracked files under `rust/`, `scripts/`,
`.github/`, `docs/`:

```
$ rg --no-heading -n '\bwallet\b|Wallet|WALLET' rust/ scripts/ .github/ docs/
~4,250 matches
```

Of those:
- Decision-log + CHANGELOG history: ~1,800 matches (class **(d)**)
- File-format primitives + crypto-pq `wallet_envelope` /
  `wallet_state` modules: ~1,400 matches (class **(a)**)
- Deferred FFI C ABI / C++ JSON-RPC surface: ~600 matches (class
  **(c)**)
- File extension / on-disk path mentions: ~120 matches (class **(b)**)
- Prose / domain-noun: ~330 matches (class **(e)**)

## What is *not* present

A grep for *orchestrator-shaped* `Wallet` types — `Wallet<S>`,
`WalletSignerKind`, `WalletCoreError`, `OpenedWallet`,
`WalletCreateParams` — returns no matches in `rust/`. The
mechanical rename of the orchestrator type and its supporting
crates is complete.

```
$ rg --no-heading -n '\bWallet<S>|WalletSignerKind|WalletCoreError|OpenedWallet|WalletCreateParams' rust/
(no matches)
```

## How to reproduce

```
cd /path/to/shekyl-core
rg --no-heading -n '\bwallet\b|Wallet|WALLET' rust/ scripts/ .github/ docs/ \
  | rg -v '(WalletFile|WalletLedger|WalletPrefs|WalletEnvelope|WalletOutput|WalletState|wallet_envelope|wallet_state|wallet2|Wallet2|ShekylWallet|WALLET_FILE|\.wallet)' \
  | rg -v 'V3_WALLET_DECISION_LOG|CHANGELOG'
```

The remaining matches should all be class **(e)** prose-style
mentions; if a match resembles an orchestrator-shaped `Wallet*` type
or a `shekyl_wallet_*` symbol that is not on the deferred-work list,
that is a rename completeness bug.

## Cross-references

- Decision log: `docs/V3_WALLET_DECISION_LOG.md` *"Wallet → Engine
  rename"* (2026-04-27).
- CHANGELOG: `docs/CHANGELOG.md` `[Unreleased]` `### Changed
  (BREAKING)`.
- Deferred work: `docs/FOLLOWUPS.md` "V3.2 — Rust cutover and
  cleanup" entries on FFI C ABI rename and C++ JSON-RPC method-name
  rename.
