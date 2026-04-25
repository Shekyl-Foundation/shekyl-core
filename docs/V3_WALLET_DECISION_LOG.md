# V3 Wallet Decision Log

**Append-only.** Every binding architectural decision for the Shekyl V3
wallet stack — `shekyl-wallet-core`, `shekyl-wallet-file`,
`shekyl-wallet-state`, `shekyl-scanner`, `shekyl-tx-builder`,
`shekyl-proofs`, `shekyl-cli`, `shekyl-wallet-rpc`, and the GUI/mobile
wallets that consume them — gets one entry here, dated, with a rationale
that survives the chat log it was decided in.

The point is anti-rewrite-the-history defense. Twelve months from now,
when someone (you, a successor maintainer, a code reviewer) asks "why
doesn't Shekyl support payment IDs?" or "why does the RPC use a flat
subaddress index instead of `{account, index}`?", the answer must live
here in one searchable place. Without that, the rationale lives in
scattered plan documents and chat transcripts, and someone three years
from now will reverse one of these decisions because they cannot find
the original reasoning and assume it was arbitrary.

## Discipline

- **Append-only.** Existing entries are not edited or removed. If a
  decision is later overturned, append a new entry with the same topic,
  date the reversal, and link both directions.
- **Date every entry.** ISO-8601 (`YYYY-MM-DD`) on the heading line.
- **Rationale, not just decision.** Every entry answers "what" and
  "why." If the "why" is "alternative X was rejected because Y," name
  X and Y.
- **Cite the plan.** When a decision originates in a `.cursor/plans/`
  document, link it. When it originates in a chat, paraphrase the
  argument; do not link transient sources.
- **Authority.** Decisions in this log are binding for new code. A PR
  that contradicts a decision here either (a) cites a follow-up entry
  that supersedes it, or (b) is rejected pending a new decision-log
  entry that overturns the old one.

---

## 2026-04-25 — Wallet stack greenfield Rust rewrite (supersedes incremental rewire)

**Decision.** The Monero-inherited `wallet2.cpp` C++ wallet is replaced
by a greenfield Rust wallet stack. Incremental in-place rewiring of
`wallet2.cpp` (the `wallet-state-promotion` plan, sub-commits 2l/2m/2n)
is halted. The replacement plan is
[shekyl-v3-wallet-rust-rewrite](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md).

**Rationale.** Two converging signals:

- Each `wallet2.cpp` rewire commit was finding a latent
  Monero-inherited bug at finer granularity (most recently the
  `tx_pool.cpp::get_relayable_transactions` Dandelion++ relay
  timestamp silent-rollback finding). Discovery rate of bugs in
  legacy code rises with audit depth, which is good for finding
  bugs and bad for shipping a freeze. The "complete the rewire,
  then audit" plan was producing audit work disguised as rewire
  work.
- Every fix landed in `wallet2.cpp` is a transcription hazard for
  the rewrite that will eventually delete it: a Rust port that reads
  the patched C++ as the spec preserves the symptom-fix but loses
  the structural lesson (e.g., "`LockedTXN` should be a typed
  consume-on-commit value, not a runtime discipline"). The cheapest
  audit is the rewrite itself, designed correctly from the start.

**Rejected alternatives.**

- "Finish the wallet-state-promotion plan first, then rewrite from a
  cleaner `wallet2.cpp`." The cleaner `wallet2.cpp` does not exist;
  every commit aimed at cleaning it surfaces more rot. The only
  clean state is "deleted."
- "Maintain `wallet2.cpp` indefinitely as a reference, port piecewise."
  Piecewise port produces partially-rewired hybrids that are worse
  than either endpoint.

**Consequence.** `wallet2.cpp` carries dead legacy code (boost cache
ser/des, JSON keys ser/des, `account_base::load_from_shkw1`, etc.) for
the remainder of its life. Phase 5 of the rewrite deletes all of it
in a single commit alongside the C++ wallet itself.

---

## 2026-04-25 — Wallet stack: cross-cutting locks (Phase 0 review-gate decisions)

The following are binding for the rewrite. Each is a single sentence
of "what" plus a paragraph of "why." Subsequent entries refine
specifics.

### Async runtime: tokio multi-threaded, caller-provided

Wallet I/O methods (refresh, send/submit, address-book RPC ops) are
`async`. Pure compute (balance from in-memory ledger, address
formatting, key-image precomputation against held secrets) stays
synchronous. The `tokio` runtime is not constructed by `Wallet`; the
caller (`shekyl-cli`'s `#[tokio::main]`, `shekyl-wallet-rpc`'s
multi-threaded `Runtime`) provides it. Multi-threaded is required by
`axum` for the RPC server and is inherited by the CLI under Shape B
(see "Agent mode: Shape B" below).

**Why caller-provided?** Tests can run `Wallet` without a runtime,
binaries control runtime configuration (worker thread count, blocking
pool size) without `Wallet` having an opinion, and "the wallet owns
the runtime" is a footgun for hosts that already have one.

### Error types: per-domain in `shekyl-wallet-core`, single `WalletRpcError` at the RPC boundary

The domain layer (`shekyl-wallet-core`) ships per-operation error
enums (`SendError`, `RefreshError`, `OpenError`, etc.) implementing
`std::error::Error`. The RPC layer wraps these in a single
`WalletRpcError` enum that maps onto JSON-RPC error codes; the code
allocation table lives in `docs/api/wallet_rpc.yaml` (the OpenAPI
spec) alongside method definitions.

**Why per-domain?** A single mega-enum is easy to match exhaustively
but couples every operation to every other operation's error
vocabulary. Per-domain enums keep `Wallet::send` callers from having
to consider `Wallet::refresh` failure modes.

**Why single boundary error?** JSON-RPC error code allocation is a
contract; the OpenAPI spec captures the contract once, the
`From<DomainError> for WalletRpcError` impls translate without each
RPC handler inventing its own mapping. Without this, the code
allocation drifts per-method.

### Locking discipline: `RwLock<Wallet>`, writer-preferred, `&mut self` for mutators

Mutating methods on `Wallet` take `&mut self`. Query methods take
`&self`. The RPC server holds `Arc<RwLock<Wallet>>` with a
writer-preferred policy (`tokio::sync::RwLock` or `parking_lot` with
the `arc_lock` feature). Refresh acquires the write lock only briefly
to merge a `ScanResult` (see "ScanResult type" below) — the long
network/scan work happens against a read snapshot or against
out-of-band state owned by the scanner task.

**Why writer-preferred?** Without writer preference, a steady stream
of read RPCs (e.g., balance polling from a UI) starves out the
refresh task indefinitely. Writer preference ensures refresh
progresses even under contention.

**Why brief writer lock for refresh?** A long-held write lock during
network sync makes every read RPC stall for the duration of a block
fetch. Splitting refresh into "scan against a read snapshot, produce a
`ScanResult`, take the write lock to apply the result, drop" bounds
write-lock duration to milliseconds even on long syncs.

### `PendingTx` lifecycle: chain-state-tagged, reservation-bearing, three-method API

`Wallet` exposes three methods for transaction sending:

```rust
fn build_pending_tx(&mut self, request: TxRequest) -> Result<PendingTx, BuildError>;
fn submit_pending_tx(&mut self, pending: PendingTx) -> Result<TxHash, SubmitError>;
fn discard_pending_tx(&mut self, pending: PendingTx) -> Result<(), DiscardError>;
```

`PendingTx` is process-local (not persisted to the wallet file) and
carries chain-state tags (`built_at_height`, `built_at_tip_hash`,
`fee_atomic_units`) so submit can refuse on reorg-after-build. Build
reserves the inputs it selected — concurrent `build_pending_tx` calls
will not double-spend the same outputs against in-flight pending txs.
`discard_pending_tx` releases the reservation. `Wallet::close` errors
if outstanding `PendingTx` reservations exist; the caller must commit
or discard each one.

**Why chain-state tags instead of TTL?** TTL is arbitrary ("5 minutes
because that felt right") and breaks on slow network or fast block
time. Chain state is the actual safety property: if the tip changed
between build and submit such that the inputs may have been spent or
the fee market may have moved, refuse. The user re-builds against
fresh state.

**Why explicit `discard_pending_tx`?** Without it, the caller's two
options are "submit" (commit the reservation by spending) or "leak"
(let the reservation linger until `Wallet::close`, blocking re-spend
of the inputs). Discard is the third state — "user cancelled the
transfer, return the inputs to the spendable pool now."

**Why error on close with outstanding pending?** Silent abandon on
close means the user can build a transfer, navigate away, and lose
the spend reservation in a way that's invisible. Explicit error makes
the leak visible at API time.

### Network type: closed enum, wallet-authoritative, daemon-verified at open

`Network` is a closed enum (`Mainnet | Testnet | Stagenet | Fakechain`),
no feature-flag exclusion. The wallet file's region 1 capability bits
declare the network the wallet was created for. `Wallet::open` requires
a `DaemonRpcClient` whose declared network matches the wallet's; the
match is verified by a `get_info` RPC call before any wallet operation
runs. Mismatch is a typed `OpenError::NetworkMismatch { wallet,
daemon }`, not a warning.

**Why closed enum, no feature flag?** Feature-flag networks ("compile a
mainnet-only build that physically cannot connect to testnet") sound
defensive but produce a build matrix where one binary type silently
misbehaves on testnet RPCs. One enum, one binary, runtime check.

**Why daemon-side verification, not just URL parsing?** A DNS hijack
pointing a "mainnet" wallet at a testnet daemon must fail before the
wallet trusts the daemon's tip. `get_info` fails fast.

### Fee priority: simplified taxonomy, daemon-supplied named estimates

`TxRequest::priority` is one of `Economy | Standard | Priority |
Custom { fee_atomic_units }`. Each named priority maps to a
**daemon-supplied named estimate** from a `shekyld get_fee_estimates`
RPC (Phase 0 prerequisite — see
[`docs/SHEKYLD_PREREQUISITES.md`](./SHEKYLD_PREREQUISITES.md)). The
wallet does not multiply a base fee by hardcoded priority factors. A
wallet-side sanity ceiling caps any estimate at 10× the previous block's
median fee per byte to defend against a daemon returning absurd numbers.

**Why simpler taxonomy than wallet2's `Default | Unimportant | Normal |
Elevated | Priority`?** Five levels produces support questions ("what's
the difference between Elevated and Priority?") that the underlying
mempool dynamics do not justify. Three named levels plus a custom
escape hatch is the shape every wallet UX converges on.

**Why daemon-supplied estimates instead of multipliers?** Hardcoded
multipliers go stale every time the fee-market dynamics change. The
daemon already observes the mempool and can compute realistic per-bucket
estimates; the wallet should consume them, not invent them.

### Subaddress hierarchy: flat, no account level

The subaddress index space is flat: `SubaddressIndex(u32)`. There is
no account level. The RPC contract surfaces subaddresses as `{"index":
u32, "label": Option<String>}`, not `{"account": u32, "index": u32}`.

**Why drop the account level?** Most users use one account; the
two-level hierarchy is wallet2 baggage from the era before
subaddresses existed. Exchanges that need stronger isolation than
"subaddresses share keys" use multiple wallet files (which have
independent keys), which is genuinely stronger isolation than
account-level subaddresses ever provided. Locking the flat shape now
keeps the JSON contract simple for the next decade.

### `RefreshHandle`: cancel-on-drop RAII, one-at-a-time, scanner checkpoints between blocks

`Wallet::refresh()` returns a `RefreshHandle` that cancels the refresh
on drop (RAII, no explicit cancel call required). At most one refresh
runs at a time per wallet — enforced by `&mut self` on `refresh`. The
scanner saves checkpoint state between blocks, so a cancelled refresh
resumes from the last fully-scanned block on next call rather than
restarting from `restore_from_height`.

**Why cancel-on-drop?** Forgotten refreshes are a class of resource
leak; RAII makes the lifetime visible at the type system.

**Why one-at-a-time?** Concurrent refreshes against the same wallet
race on `apply_scan_result` and produce torn ledger state. The
constraint is enforced for free by `&mut self`.

### Wallet send confirmation: three-method, confirmation in client

The CLI and GUI confirmation prompt uses the same three-method API:
display the `PendingTx` (recipient, amount, fee, expected confirms),
ask the user, then call `submit_pending_tx` or `discard_pending_tx`.
The RPC has no confirmation concept — it never blocks waiting for
user input. Confirmation is purely a client-side concern.

**Why?** A blocking confirmation in the RPC layer is incompatible
with both UI patterns: CLI wants synchronous prompt, GUI wants modal
dialog with cancel button. Pushing confirmation out keeps the RPC
surface uniform.

### Logging: `tracing`, structured JSON, two-layer secret redaction

The `tracing` crate is the logging substrate. Production output is
structured JSON; development output is the default
`tracing-subscriber` formatter. Log level is controlled by `RUST_LOG`,
no in-wallet config knob. Secret redaction is two-layer:

1. **Type-level.** Secret-bearing types (`SecretSpendKey`,
   `SecretViewKey`, `Mnemonic`, etc.) implement `Debug` and `Display`
   to emit a redacted placeholder (`"<SecretSpendKey redacted>"`),
   do not derive `Serialize`/`Deserialize`, and expose the bytes only
   via an explicit `expose() -> &SecretStr` method that callers must
   reach for deliberately.
2. **Subscriber-level.** A `tracing-subscriber` field formatter layer
   matches a small allowlist of field names (`secret`, `private_key`,
   `seed`, `password`) and redacts the value regardless of the type
   it came in as. Defense-in-depth against a future `Debug` derive
   on a struct that holds a secret-by-value.

**Why two layers?** One is too few. Type-level is the primary
defense, but a `Debug` derive added later (or a `format!("{:?}",
struct)` that pulled in a non-redacted field) bypasses it. The
subscriber layer is a backstop. Tests assert that both layers fire.

### Config file handling: TOML, layered precedence, XDG paths

`shekyl-wallet-rpc` and `shekyl-cli` read configuration from (in
descending precedence):

1. CLI flags (`--bind-address`, `--daemon-url`, etc.).
2. Environment variables (`SHEKYL_WALLET_RPC_BIND_ADDRESS`,
   `SHEKYL_DAEMON_URL`, etc.). One env var per flag, prefixed.
3. TOML config file at `~/.config/shekyl/wallet-rpc.toml` (or
   `--config <path>` to override).
4. Built-in defaults.

Paths are resolved via the [`directories`](https://crates.io/crates/directories)
crate (XDG-compliant on Linux/BSD, platform-native elsewhere): wallets
in `~/.local/share/shekyl/`, config in `~/.config/shekyl/`, UDS socket
in `$XDG_RUNTIME_DIR/shekyl.sock`. All defaults overridable via the
precedence chain above.

**Why this precedence order?** It matches every modern CLI/daemon
convention (kubectl, cargo, systemd). Reverse-precedence ("config
file overrides CLI flag") is universally surprising; do not invent
a Shekyl-specific order.

### KAT regression CI: plain tests, dedicated files, `CODEOWNERS` + branch protection

Test vectors (the Tier-1/2/3/4 KAT corpus from the freeze plan) are
exercised by **plain `cargo test` runs**, not behind a
`--features kat-regression` flag. The tests live in dedicated files
(`tests/kat_*.rs`) so reviewers can identify changes by path. Slow
KATs are gated by `#[ignore]` and run via `cargo test --
--include-ignored` in CI. The corpus files (`docs/test_vectors/**`)
and the test files (`tests/kat_*.rs`) are protected by `CODEOWNERS`,
and `dev` has branch protection requiring PR review.

**Why plain tests, not feature-flagged?** Feature flags create the
"forgot to enable the flag" failure mode where a contributor runs
`cargo test`, sees green, and ships a KAT regression. Plain tests
fire on every test run.

**Why `#[ignore]` for slow ones?** Some KATs (e.g., FCMP++ proof
verification across the full Tier-3 corpus) are long. Gating them
behind `#[ignore]` keeps interactive `cargo test` fast; CI runs with
`--include-ignored` so they fire on every PR regardless.

**Why `CODEOWNERS` + branch protection?** A KAT update that the
maintainer didn't review is a corpus poisoning vector. The test
infrastructure (dedicated paths, mandatory review) makes that vector
visible and procedurally blocked.

---

## 2026-04-25 — Payment IDs and integrated addresses: dropped entirely

**Decision.** The V3 wallet does not support integrated addresses or
payment IDs. `TxRequest` does not carry a `payment_id` field. The
`PaymentId` type does not exist in `shekyl-wallet-state`.

**Rationale.** Payment IDs were a Monero compatibility wart: they
existed because Monero originally had no subaddresses and needed a
way to attach a per-recipient marker to "send to this address."
Subaddresses solved that problem without payment IDs. Modern Monero
only carries payment IDs for backwards compatibility with old
exchange integrations that haven't migrated. Shekyl V3 is pre-launch:
there are no users who depend on payment IDs, by definition. The
right time to drop the wart is before the first user adopts it.

**Rejected alternatives.**

- "Keep payment IDs in case some future exchange wants them." This
  is preservation theater. The correct answer to a future exchange
  asking for payment IDs is "subaddresses give you per-recipient
  tracking with stronger privacy properties; here's the integration
  guide." That answer is much harder to give if Shekyl shipped
  payment IDs and now has to deprecate them.

**Consequence.** Subaddress-per-recipient is the only mechanism for
exchange-style "tag this incoming payment with a customer identifier."
Documentation in `docs/USER_GUIDE.md` and `docs/WALLET_RPC_README.md`
explains the pattern.

---

## 2026-04-25 — Cold-wallet flow: kept, reshaped via typed bundles

**Decision.** Air-gapped (offline-signing) wallets are a supported
flow in the V3 wallet stack, distinct from hardware-offload mode.
The export/import dance uses two typed file artifacts:

- `UnsignedTxBundle`: produced by the watch-only wallet on the
  network-connected machine; contains the unsigned transaction,
  selected inputs, and the metadata needed for offline signing.
- `SignedTxBundle`: produced by the offline signing wallet; contains
  the signed transaction ready for relay.

The flow is a two-step CLI/RPC pattern: `wallet build_unsigned --out
unsigned.bundle` on the network side; offline machine signs with
`wallet sign-bundle unsigned.bundle --out signed.bundle`; relay with
`wallet submit-signed signed.bundle`.

**Rationale.** "Air-gapped" and "hardware-offload" are two distinct
threat models:

- **Hardware-offload** trusts a Ledger/Trezor to sign in real-time
  over USB. Bytes never leave the host except as a finalized signed
  transaction.
- **Air-gapped** does not trust the network-connected machine with
  spend keys at all. Signing happens on a separate machine that has
  never touched the network. File-based handoff is the connecting
  mechanism.

Hardware-offload does not subsume air-gapped. The two flows are kept
separate; the air-gapped flow is reshaped from wallet2's
`export_outputs` / `import_outputs` / `export_key_images` /
`import_key_images` (four endpoints, two file formats) to a single
typed `UnsignedTxBundle` / `SignedTxBundle` pair (two endpoints, two
typed files).

**Rejected alternatives.**

- "Drop air-gapped flow; tell users to use a hardware wallet." Cuts
  off a legitimate threat model (don't trust hardware vendors) and
  is a privacy-product regression for the most security-conscious
  users.
- "Keep wallet2's four-endpoint shape for compatibility." There are
  no V3 users with stored unsigned/signed bundles in wallet2 format;
  shipping the cleaner two-bundle shape is free.

---

## 2026-04-25 — Agent mode: Shape B (CLI is always a thin client to wallet-rpc)

**Decision.** `shekyl-cli` is structurally a thin client to
`shekyl-wallet-rpc`. There is one wallet-bearing process type in the
system. The CLI's two modes are:

- **One-shot mode.** `shekyl-cli balance` (no agent running) spawns
  an in-process `shekyl-wallet-rpc` instance, runs the command
  against it, shuts it down, and exits.
- **Agent mode.** `shekyl-wallet-rpc --uds /path/sock my.wallet`
  starts a long-running RPC daemon. `shekyl-cli --rpc-url uds:///path/sock
  balance` is a remote client to it.

The CLI does not directly own a `Wallet` instance; every command goes
through the same RPC handler that the GUI/mobile clients use.

**Rationale.** Shape A (CLI owns its own `Wallet`, agent mode is a
flag on `shekyl-cli`) produces two genuinely different code paths
that need parallel testing. Shape B unifies them: the same RPC
handlers serve CLI, GUI, mobile, and external integrations. The CLI's
one-shot mode is a 30-line `Runtime::new() ; spawn rpc ; call ; drop`
shim; agent mode is the same shim against an existing daemon. Same
business logic on both paths.

**Rejected alternatives.**

- Shape A: "CLI owns its own Wallet, agent mode is a flag on
  `shekyl-cli`." The unification is fake — CLI and RPC share types
  but not call paths, so a bug fix to one might miss the other. Shape
  B makes the unification real.

**Consequence.** `shekyl-cli` cannot do anything `shekyl-wallet-rpc`
does not expose. The OpenAPI spec is the contract for both. CLI
features that have no RPC equivalent (e.g., interactive REPL state)
live entirely in the CLI's client-side concerns; they don't reach
into wallet logic.

---

## 2026-04-25 — RPC JSON shape: Shekyl-native, OpenAPI-first

**Decision.** The `shekyl-wallet-rpc` JSON-RPC API uses
**Shekyl-native** data shapes designed for the V3 feature set, not
shapes designed for compatibility with Monero's `wallet_rpc_server`.
The OpenAPI spec at `docs/api/wallet_rpc.yaml` lands **before or
alongside** the first method implementation in Phase 4b of the
rewrite plan; the implementation conforms to the spec, not the
reverse.

Shekyl-native examples:

- **Subaddress index.** `{"index": u32, "label": Option<String>}`
  (flat). Not `{"account": u32, "index": u32}`.
- **Balance.** `{"liquid": u64, "staked": u64, "unlocked": u64,
  "claimable_rewards": u64}` — atomic units, no float, staking
  explicit.
- **Capability mode.** First-class field on `wallet info` responses
  (`"mode": "spend" | "watch_only" | "spend_via_hardware"`),
  not inferred from the absence of a spend key.
- **PQC auth state.** First-class fields where relevant, not
  shoehorned into wallet2's auth-token model.

**Rationale.** The RPC contract is the GUI/mobile integration
surface for the next decade. Designing it to be partially-compatible
with Monero's `wallet_rpc_server` produces a worst-of-both-worlds
API: not compatible enough to be a drop-in replacement (the
underlying data model is too different), not native enough to express
V3-specific concepts cleanly (staking, capability modes, PQC auth
have no clean place in the legacy shape). Pick one. Shekyl-native is
the only one that survives the V4 lattice-only transition without a
second redesign.

**Rejected alternatives.**

- "Match wallet_rpc_server's shapes for tooling compatibility." The
  tooling that consumes wallet_rpc_server already knows how to
  rewrite shapes for new endpoints (Trezor Suite, etc.). The cost
  of one-time integration effort is much lower than the cost of a
  permanent contract that doesn't fit Shekyl's data model.

**Consequence.** Existing Monero ecosystem tooling does not work
against `shekyl-wallet-rpc` out of the box. A separate plan can
ship a compatibility shim if a specific integration partner needs
one; the default contract is Shekyl-native.

---

## 2026-04-25 — Phase 5 deletion scope: includes Rust FFI surfaces consumed only by C++

**Decision.** The single-commit Phase 5 deletion of `wallet2.cpp` and
related C++ files **also** deletes the Rust-side FFI surfaces whose
only consumer was C++ `wallet2.cpp`. Specifically:

- `rust/shekyl-ffi/src/wallet_ledger_ffi.rs` (the typed cache-handle
  FFI from sub-commit 2l.a). Its only consumer was the never-written
  `wallet2_handle_views.h/.cpp`.
- `rust/shekyl-ffi`'s `shekyl_wallet_*` C-ABI symbols (the open / save
  / save-as / rotate-password / change-password handle surface from
  sub-commits 2j and 2k). With C++ wallet2 deleted, these symbols
  have no callers.
- `src/shekyl/shekyl_ffi.h` declarations for the wallet operations
  above. (The header itself stays; daemon FFI continues to use it.)
- C++ tests that exercised the FFI shape (`tests/unit_tests/shekyl_ffi_*.cpp`
  if any).
- `account_base::load_from_shkw1` and `forget_master_seed` (the
  transitional C++ helpers added in sub-commit 2k.a Phase 2).

**Rationale.** The general rule: if a Rust symbol exists only because
C++ called it, and C++ is deleted, the Rust symbol is deleted in the
same commit. The FFI surface is part of the C++ surface as far as
deletion is concerned. Leaving dead `extern "C"` exports in
`shekyl-ffi` because "we might need them later" violates the same
rule that motivates Phase 5 in the first place — "later" is vague,
the FFI surface is permanent overhead.

**Consequence.** Phase 5 is mechanically a larger commit than just
"delete the C++ files." The PR description must enumerate the Rust
FFI symbols deleted alongside, and reviewers must confirm none of
them have non-C++ callers. The
[shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md)
Phase 5 task list captures the full enumeration.

---

## 2026-04-25 — Stake lifecycle: substantive state machine, persisted in `WalletLedger`

**Decision.** Stake instances are a first-class persisted type in
`WalletLedger`, not a thin wrapper. The structure is approximately:

```rust
pub struct StakeInstance {
    id: StakeId,
    amount_atomic: u64,
    state: StakeState,
    // ... cryptographic material, lock heights, etc.
}

pub enum StakeState {
    PendingBroadcast { built_at_height: u64 },
    Unconfirmed { broadcast_at_height: u64, broadcast_tx: TxHash },
    Locked { locked_until_height: u64 },
    Accruing { last_reward_height: u64, accrued_atomic: u64 },
    Claimable { available_at_height: u64 },
    Unstaking { unstake_initiated_at_height: u64 },
    FullyUnstaked { unstaked_at_height: u64 },
}
```

The state machine is reconciled on `apply_scan_result`: each scan
result carries observed events (broadcasts seen, locks expired,
rewards accrued, unstake transactions confirmed) and the merge logic
advances `StakeState` accordingly.

**Rationale.** The original plan sketch treated stakes as "thin
wrappers around a transaction hash," which is what wallet2 would
have done. Wargaming the lifecycle revealed that stakes are
fundamentally different from regular transactions:

- They have **asynchronous accrual** — rewards land on the wallet
  over many blocks without any wallet-initiated action.
- They have **multi-stage timing** — `Locked` → `Accruing` →
  `Claimable` is gated on chain heights and reward conditions,
  not on the user's confirm-to-submit flow.
- They have **partial recoverability** — `Unstaking` may take many
  blocks to drain; the wallet must distinguish "unstake initiated"
  from "unstake completed."

A thin wrapper produces ad-hoc state inference at every read site
("is this stake claimable? compute from scratch by walking the
chain"). The state-machine shape produces consistent observable
state ("`StakeState::Claimable` means claimable, period") and
moves the inference into the merge logic where it belongs.

**Consequence.** `WalletLedger` schema versioning must include
`StakeInstance` from the start; later additions to `StakeState`
require schema migrations. The migration discipline is captured in
the freeze plan; this entry is its consumer.

---

## 2026-04-25 — `ScanResult` type: typed scanner output, additive merge into `WalletLedger`

**Decision.** `shekyl-scanner::ScanResult` is the typed value that
the scanner produces and `Wallet::apply_scan_result` consumes. It
is an **additive-only** structure: every variant represents an
event the ledger learned about (new transfer detected, key image
observed, stake reward accrued, reorg-rewind needed up to height
H). `apply_scan_result` merges these into `WalletLedger` under the
write lock; merge logic is the single place where ledger state
changes during refresh.

```rust
pub struct ScanResult {
    pub processed_height_range: Range<u64>,
    pub new_transfers: Vec<DetectedTransfer>,
    pub spent_key_images: Vec<KeyImageObserved>,
    pub stake_events: Vec<StakeEvent>,
    pub reorg_rewind: Option<ReorgRewind>,
    // ... typed event vocabulary
}
```

**Rationale.** Wallet2 mutates `WalletLedger` (well, its C++
equivalents) directly during scan, with locking discipline scattered
across the scan loop. The `ScanResult` shape concentrates the mutation
into one method (`apply_scan_result`), which has three benefits:

- **Bounded write-lock duration.** The scanner runs against a read
  snapshot of the ledger and produces a `ScanResult` without holding
  the write lock. The merge takes the write lock only to apply the
  result. Read RPCs do not stall during long syncs (see "Locking
  discipline" above).
- **Typed event vocabulary.** Adding a new ledger event (e.g., a
  new staking-related observation) is a `ScanResult` enum extension
  + an `apply_scan_result` match arm + a scanner emission site, all
  type-checked. Compare to wallet2's "scattered side effects" model
  where adding an event means hunting for every code path that
  scans.
- **Cancellable scans.** A `RefreshHandle` drop cancels the scanner
  before any partial `ScanResult` is applied. Either the full result
  applies or nothing applies. No torn state.

**Rejected alternatives.**

- "Direct mutation of `WalletLedger` from the scanner." The
  bounded-write-lock and torn-state arguments above. Unsalvageable
  for the writer-preferred RwLock model.
- "`ScanResult` is just a typedef for `WalletLedger`." Loses the
  additive-only constraint and the typed event vocabulary; the
  merge becomes "overwrite," which is wrong on reorg.

---

<!-- Append new entries above this line. Date format YYYY-MM-DD. -->
