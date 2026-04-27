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

## 2026-04-25 — Subaddress JSON shapes: two schemas, no label join in transfer records

**Decision.** The `shekyl-wallet-rpc` JSON contract carries
subaddress indices in **two distinct shapes** depending on whether
the response is chain-state or display-state:

- **Bare form.** `{"index": u32}`. Used by every response that is a
  projection of chain-state — transfer records, pending-tx
  descriptors, scanner outputs. Labels are wallet-state, not
  chain-state, and joining them into chain-state shapes conflates
  layers that need to stay separate (a label rename is not a
  ledger event).
- **Joined form.** `{"index": u32, "label": Option<String>}`. Used
  by the address-list / "list addresses" endpoints and similar
  display-oriented surfaces that exist to render addresses for the
  user. The label is joined from
  `BookkeepingBlock::subaddress_labels.per_index` at handler time;
  if no label is set, `null` is returned.

The Phase 4b OpenAPI spec lands these as two named schemas
(`SubaddressIndexRef` for the bare form, `SubaddressLabeled` or
similar for the joined form) so reviewers and integrators can see
the distinction at the schema level.

**Rationale.** Without the factoring, every JSON shape that
mentions a subaddress index drifts toward also carrying the label
"because the GUI wants it." That couples chain-state shapes to
wallet-state, makes transfer records bigger than they need to be,
and forces the daemon-RPC-only consumer (block explorers, indexer
services) to receive labels they have no business seeing. Forcing
the label join to happen only at handler boundaries — and only for
endpoints whose explicit purpose is rendering — keeps internal
shapes clean and the join site auditable.

The flat-namespace decision (above) already locked `index` as the
single field name; this entry locks where labels do and do not
travel with it.

**Rejected alternatives.**

- Always include the label. Couples chain-state to wallet-state and
  forces the join into every handler.
- Always exclude the label, render it client-side. Pushes wallet
  state through every consumer that wants to display addresses;
  defeats the point of the RPC.

**Consequence.** Phase 4b ships `SubaddressIndexRef` and a
labeled-variant schema; transfer-record responses use the bare
form, address-list responses use the joined form. Future endpoints
choose one factoring and document why.

---

## 2026-04-25 — Phase 5 deletion scope: includes Rust FFI surfaces consumed only by C++

**Decision.** The single-commit Phase 5 deletion of `wallet2.cpp` and
related C++ files **also** deletes the Rust-side FFI surfaces whose
only consumer was C++ `wallet2.cpp`. Specifically:

- `rust/shekyl-ffi/src/wallet_ledger_ffi.rs` (the typed cache-handle
  FFI from sub-commit 2l.a). Its only consumer was the never-written
  `wallet2_handle_views.h/.cpp`. **Pre-empted on 2026-04-25** during
  the Phase 1 `primitives` task once the `SubaddressIndex` flatten
  work confirmed zero `.cpp` callers; see the *"Phase 5 pre-emption
  rule + first application"* entry below. The Phase 5 commit's
  deletion list excludes this file.
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

**Decision.** `shekyl_wallet_core::scan::ScanResult` is the typed
value that `Wallet::apply_scan_result` consumes during refresh. It
is an **additive-only** structure: every variant represents an
event the ledger learned about (new transfer detected, key image
observed, stake reward accrued, reorg-rewind needed up to height
H). `apply_scan_result` merges these into `WalletLedger` under the
write lock; merge logic is the single place where ledger state
changes during refresh.

```rust
pub struct ScanResult {
    pub processed_height_range: Range<u64>,
    pub parent_hash: Option<[u8; 32]>,
    pub block_hashes: Vec<(u64, [u8; 32])>,
    pub new_transfers: Vec<DetectedTransfer>,
    pub spent_key_images: Vec<KeyImageObserved>,
    pub stake_events: Vec<StakeEvent>,
    pub reorg_rewind: Option<ReorgRewind>,
}
```

`block_hashes` carries one entry per height in
`processed_height_range`, not just one per block that produced
events: the persisted ledger advances `synced_height` exactly once
per scanned block and the merge needs the block hash for every
height to drive `LedgerIndexes::ingest_block`. This is the smallest
shape that supports an "every block in range is fully ingested"
contract; a per-event-only sketch was rejected because it loses
the per-height advance for empty blocks.

**Crate location.** The type lives in `shekyl-wallet-core::scan`,
not in `shekyl-scanner`. `ScanResult` is a *wallet-domain event
vocabulary* (the merge contract `apply_scan_result` consumes); the
scanner produces it but does not own its semantics, exactly as
`RefreshError` lives in `shekyl-wallet-core` even though the
scanner can drive a refresh. Pinning the home in the consumer
crate keeps `shekyl-scanner` import-free of wallet-orchestrator
concerns and lets the producer surface evolve in Phase 2a without
touching the consumer contract. (An earlier draft of this entry
named `shekyl-scanner::ScanResult`; corrected here per the
"consumer contract pinned, producer side left to evolve" rule.)

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

## 2026-04-26 — `Wallet::apply_scan_result` invariants and Wallet-side `LedgerIndexes`

**Decision.** `Wallet::apply_scan_result(&mut self, result: ScanResult)
-> Result<(), RefreshError>` enforces two invariants before applying
any event from the result. Both failures map to
`RefreshError::ConcurrentMutation`, which is the typed retry signal
to a polling caller.

1. **Start-height equality.** When `result.reorg_rewind` is `None`,
   `result.processed_height_range.start == self.synced_height() + 1`.
   When `result.reorg_rewind` is `Some(rewind)`, the scanner replays
   from the fork point, so the expected start is `rewind.fork_height`
   instead (the rewind step sets `synced_height` to `fork_height - 1`
   before any per-height events apply). Catches the case where a
   second refresh raced ahead between the snapshot the scanner saw
   and the write-lock window the merge takes.

2. **Parent-hash chain.** When `start > 1`, `result.parent_hash` is
   `Some(h)` where `h == self.ledger.ledger.block_hash_at(start - 1)`.
   When `start == 1` (genesis), `result.parent_hash` must be `None`.
   Heights below `fork_height` survive a reorg rewind unchanged, so
   this check applies in both the rewind-present and rewind-absent
   branches without needing a special case. Catches the case where
   the wallet's recorded chain at the start point shifted under the
   scanner — e.g., an unrelated reorg-rewind landed between snapshot
   and merge — without surfacing as a height mismatch.

3. **Per-height block-hash record.** `result.block_hashes` carries
   one entry per height in `processed_height_range` (ascending,
   exactly once). The merge requires every height's hash because
   `LedgerIndexes::ingest_block` advances `synced_height` and
   appends to `reorg_blocks` exactly once per scanned block — even
   when the block had zero events for this wallet. A missing entry
   for a height inside `processed_height_range` is itself a
   snapshot-disagreement signal and rejects with
   `ConcurrentMutation`.

A "full-range hash chain check" alternative (every block hash in
`processed_height_range` re-verified against a per-height list
carried by the result) was considered and rejected: it doubles the
in-memory size of `ScanResult` for an attack the parent-hash + the
write-lock-during-merge already preclude. The parent of `start`
plus the lock window is sufficient because: the scanner produced
its result against a `synced_height` snapshot, the merge sees the
same wallet under a write lock, and the wallet's own
`block_hash_at(synced_height)` did not move out from under it
during the lock window.

**`Wallet<S>` carries `LedgerIndexes` directly.** Per the
`RuntimeWalletState audit` entry above, the runtime indexes
(`key_images`, `pub_keys`, `staker_pool`) are reconstructible from
`LedgerBlock` + scanner replay and are never persisted. Holding
them on `Wallet<S>` (rather than passing them through every
`apply_scan_result` call site or guarding them behind a separate
`Mutex`) matches the `&self` queries / `&mut self` mutations
discipline already established for `WalletLedger`: a single `&mut
self` borrow on `apply_scan_result` mutates both the persisted and
the runtime sides atomically. The bg-sync loop's
`Arc<Mutex<LiveLedger>>` shape is a separate concern — it serves
the standalone `shekyl-scanner::sync` module that does not see a
`Wallet<S>`. `Wallet`-driven refresh (Phase 2a) goes through
`apply_scan_result` and inherits the `&mut self` guarantee.

**Rejected alternatives.**

- "Pass `&mut LedgerIndexes` through every `apply_scan_result`
  call site." Reasonable for Phase 1 testing, but every Phase 2
  caller would have to thread the parameter, and the natural
  reading of "additive merge into `WalletLedger`" gets diluted.
- "Wrap `LedgerIndexes` in `tokio::sync::Mutex`." Adds an async
  lock for state already serialized by `&mut self`. The bg-sync
  loop holds `Arc<Mutex<LiveLedger>>` because that loop does not
  see a `Wallet<S>`; once `Wallet::refresh()` lands in Phase 2a,
  the `Wallet<S>`-mediated path runs under writer-preferred
  `RwLock<Wallet<S>>` and pays no extra lock per-event.

---

## 2026-04-25 — `WalletFileHandle` renamed to `WalletFile`

**Decision.** The `shekyl-wallet-file` crate's primary type
`WalletFileHandle` is renamed to `WalletFile` in
[PR 0.2 of the rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md).
Mechanical rename across all call sites (`shekyl-wallet-file`,
`shekyl-wallet-prefs`, `shekyl-ffi`, `src/shekyl/shekyl_ffi.h`
doc-comment); no ABI change (the C-ABI symbols use the
`shekyl_wallet_*` prefix, not the Rust type name).

**Rationale.** Two reasons:

- The Phase 1 orchestrator type in `shekyl-wallet-core` is `Wallet`.
  The plan's "Wallet → WalletFile" phrasing was loose plan-text — the
  intent was to free `Wallet` for the orchestrator and rename whatever
  the file-orchestrator type was actually called to `WalletFile`. The
  realization (`WalletFileHandle` → `WalletFile`) matches the intent.
- The `Handle` suffix was inherited cruft suggesting "this is a handle
  to something" without specifying what. `WalletFile` describes the
  actual abstraction (a wallet file, with envelope, atomic IO,
  advisory locking, payload framing). The shorter name also reads
  better as a field type in the Phase 1 composition pattern
  (`pub struct Wallet { file: WalletFile, .. }` vs
  `file: WalletFileHandle`).

**Scope.** Type rename only. The C-ABI symbols and the on-disk
envelope format are untouched.

---

## 2026-04-25 — Fee priority positional mapping (implementation realization of Decision 6)

**Decision.** The Shekyl V3 wallet's three-level priority taxonomy
(`Economy | Standard | Priority`, plus `Custom(u64)`) maps to the
`shekyld` `get_fee_estimate` response's positional `fees[]` vector
as follows:

- `Economy` → `fees[0]` (= the 2021-scaling `Fl` floor tier).
- `Standard` → `fees[1]` (= `Fn`, normal-load tier).
- `Priority` → `fees[3]` (= `Fh`, high-load tier).
- `Custom(u64)` → caller-supplied per-byte atomic-units value, bypassing
  the daemon estimate but still subject to the wallet-side sanity
  ceiling (`TxError::DaemonFeeUnreasonable`-equivalent).

**Index `fees[2]` (= `Fm`, medium-load tier) is intentionally
unmapped** in the V3.0 wallet UX. See "Why skip `fees[2]`" below.

**Rationale.** This is an implementation realization of
[Decision 6 — Fee priority: simplified taxonomy, daemon-supplied named estimates](#fee-priority-simplified-taxonomy-daemon-supplied-named-estimates),
not a new policy. The PR 0.3 audit
([`docs/SHEKYLD_PREREQUISITES.md`](SHEKYLD_PREREQUISITES.md) §2)
established that `shekyld`'s `get_fee_estimate` response carries a
4-element positional `fees[]` vector, not a name-keyed map. The plan-
text language "daemon-supplied named per-bucket estimates" was loose;
on the wire the daemon supplies numbers, the wallet supplies names.
This entry pins which positional indices carry which wallet-facing
names so the binding is explicit and reviewable rather than buried in
implementation code.

**Why this mapping, in three timeframes.**

- **Now (V3.0).** Without post-launch fee-market data, the
  conservative reading of the four 2021-scaling tiers is:
  `Fl`/`fees[0]` is the floor — txs always confirm eventually but with
  no urgency guarantee; `Fn`/`fees[1]` is the typical-conditions fee
  that should confirm within a normal window; `Fh`/`fees[3]` is the
  guaranteed-confirm-under-congestion fee. Mapping `Standard` to
  `fees[1]` (rather than `fees[2]`) optimizes for the typical case at
  the cost of occasional under-payment during congestion. The
  occasional under-payment is recoverable (the user can rebuild the
  same `TxRequest` with `Priority` or `Custom`); systematic
  over-payment is not.
- **Mining era end (~30 years).** The four 2021-scaling tiers are
  consensus-shaped (block weight scaling, dynamic base fee derivation
  from Fl–Fh). The mapping is wallet-side policy and can be retuned
  per release without touching the daemon or the wire format. Mining-
  era fee dynamics — where transaction fees become the primary block
  reward — may shift the typical-vs-congested boundary, in which case
  retuning to `Standard → fees[2]` is a wallet-config change with no
  consensus impact.
- **Post-quantum era (V4).** Lattice signatures change tx size
  significantly; the four-tier daemon vector continues to express
  per-byte fees regardless of signature scheme. The mapping is
  invariant to V4.

**Why skip `fees[2]`.** The four-tier daemon vector exposes the
2021-scaling document's full graduation (Fl, Fn, Fm, Fh). A
three-tier wallet UI compresses this. The compression options are:

- `Economy=fees[0], Standard=fees[1], Priority=fees[3]` (chosen).
  Skips `fees[2]` (Fm). Standard is conservative for typical
  conditions; Priority overpays under typical conditions but
  guarantees confirm under congestion.
- `Economy=fees[0], Standard=fees[2], Priority=fees[3]`. Skips
  `fees[1]` (Fn). Standard is more aggressive — overpays under
  typical conditions but reduces stuck-tx incidence under moderate
  congestion. More expensive in the typical case.
- `Economy=fees[1], Standard=fees[2], Priority=fees[3]`. Skips
  `fees[0]`. The "I don't care when this confirms" floor is unavailable;
  every transfer pays at least `Fn`. Removes a legitimate use case
  (e.g., automated batched payouts where confirmation latency is
  not a concern).

The chosen mapping (`fees[0], fees[1], fees[3]`) preserves both ends
of the range (lowest cost, highest guarantee) and uses `fees[1]` for
the typical case. The "Standard might fall short under congestion"
risk is mitigated by typed retry: `TxError::TxStuckRebuild` (or
equivalent) prompts a wallet-side rebuild at higher priority. The
alternative "Standard always overpays for safety" failure mode has no
in-band recovery — the user has no signal that they overpaid.

**Revisit conditions.** This mapping is wallet-side policy, deliberately
captured here so future revision is informed rather than ad-hoc. Revisit
when **any** of the following hold:

- Post-launch fee data shows >10% of `Standard`-priority txs reach the
  mempool eviction window without confirming. Indicates `Standard →
  fees[1]` is too low for typical conditions; consider `Standard →
  fees[2]`.
- Post-launch fee data shows `Standard` and `Priority` confirm in
  indistinguishable median windows. Indicates `Priority → fees[3]`
  overpays without delivering perceptible benefit; consider
  `Priority → fees[2]` (with `Custom` still available for guaranteed-
  confirm cases).
- The 2021-scaling document is amended or superseded such that
  `fees[1]` and `fees[2]` no longer correspond to "normal-load" and
  "medium-load" tiers as currently defined. Indicates the daemon-side
  semantics have shifted; wallet mapping must be re-derived from the
  new document.

**Wallet-side sanity ceiling unchanged.** Per Decision 6, any `fees[i]`
that exceeds a wallet-configured per-byte maximum (default: 5x the
historical median of `fees[3]` over the last 1000 blocks observed by
the wallet, with a hard cap at 100,000 atomic units / byte to defend
against a compromised daemon returning absurd values) causes the
wallet to refuse the build with a typed error. The ceiling is
wallet-config, not daemon-config, and applies regardless of which
positional index the user-selected priority maps to.

**Rejected alternatives.** Already covered by Decision 6's rejected
alternatives (hardcoded multipliers, per-network static fees,
no-priority-at-all). The implementation-level rejection of
"parse name-keyed buckets from the daemon response" is now moot —
the daemon does not supply names; this entry establishes that the
wallet supplies them.

---

## 2026-04-25 — `shekyld` fee policy version is absent; wallet uses `Option<u32>` for forward compat

**Decision.** The Shekyl V3 wallet's representation of "what fee
policy version does the daemon claim to be running" is
`Option<u32>`. As of the PR 0.3 audit (2026-04-25), `shekyld` exposes
no fee policy version field anywhere — not on `get_fee_estimate`'s
response, not on `get_info`'s response, not as a separate RPC. The
wallet treats absence as `None` and accepts whatever fee numbers the
daemon supplies, subject to the sanity ceiling. If `shekyld` later
adds a `fee_policy_version` field (recommended target: V3.1 daemon-side
follow-up; see [`docs/SHEKYLD_PREREQUISITES.md`](SHEKYLD_PREREQUISITES.md) §3),
the wallet starts honoring it without a wire-format break: the value
is decoded into the `Option`, and the wallet refuses transaction
construction if the value strictly exceeds the wallet's
`known_max_fee_policy_version` constant (compile-time configured per
wallet release).

**Rationale.** The fee policy is what the wallet uses to convert a
priority-and-tx-shape into a per-byte fee. If the daemon's fee math
changes (different base-fee formula, different per-bucket scaling
rules, different priority-to-bucket mapping at a hard fork), the
wallet needs an in-band signal that its assumptions are stale.
Without that signal, the wallet either silently builds against
out-of-date assumptions (potentially over- or under-paying) or has to
hand-crank a binary-version-equality check between wallet and daemon
(a deployment constraint that is fine for the CLI but awkward for
GUI/mobile wallets that ship on slower update cycles).

For V3.0 launch, the absence is **not blocking**. V3.0 launches with
whatever fee policy `shekyld` has at that moment, and any subsequent
fee-policy change happens via hard fork; the wallet binary is rebuilt
and redeployed against the new `shekyld` at fork time. The wallet
binary version is implicitly the fee policy version for that launch
cycle.

After V3.0, when fee policy is potentially upgraded mid-version-cycle
(e.g., a fee-market parameter retuning at a future hard fork), the
absence of an explicit `fee_policy_version` becomes load-bearing.
The V3.1 daemon-side follow-up addresses this by adding a typed
version field. The wallet's forward-compatible shape (`Option<u32>`)
ensures the wire format stays backward-compatible whether or not the
daemon ever ships the field.

**Why `Option<u32>` rather than `u32` with a sentinel.** Sentinels
(e.g., `u32::MAX = "unknown"`) conflate "no version concept exists"
with "version concept exists but is unrecognized." `Option` is the
right Rust idiom: `None` is the unambiguous "field absent on the
wire," and the wallet's matching is exhaustive at compile time. A
sentinel-based encoding would produce silent fallthrough when the
sentinel value collides with a future legitimate version (e.g., if
the field is later introduced and reaches `u32::MAX`).

**Rejected alternatives.**

- "Hardcode wallet binary version equality with daemon binary
  version, refuse to operate against any other daemon." Too coarse:
  patch releases that touch logging or RPC unrelated to fee policy
  would unnecessarily refuse to operate. The fee policy version is a
  separate concept from the daemon binary version and deserves its
  own field.
- "Infer fee policy version from `hard_fork_info` (the consensus
  hard-fork version)." Conflates two semantic axes: a hard fork can
  change consensus rules without changing fee math, and fee math can
  be tuned without a hard fork (e.g., adjusting `FEE_ESTIMATE_GRACE_BLOCKS`
  default). The two concepts must be independently versionable.
- "Refuse to build any transaction until the daemon supplies a fee
  policy version." Breaks against current `shekyld` and any future
  daemon that hasn't shipped the V3.1 follow-up. The wallet must work
  against today's `shekyld`; the strict mode is wrong for V3.0.

**Lifecycle.** This decision is V3.0-pinned and expected to evolve.
When the V3.1 daemon-side follow-up lands, this entry gets a
companion entry (not an edit) noting that `shekyld` now supplies the
field, the wallet's `known_max_fee_policy_version` is set to the
launch value, and the wallet now refuses transactions against newer
daemon policies until the wallet binary catches up. The
`Option<u32>` shape persists indefinitely as the forward-compat
buffer for any future field-removal scenario.

**Cross-link.** Daemon-side V3.1 follow-up filed in
[`docs/FOLLOWUPS.md`](FOLLOWUPS.md) §"V3.1+ — Legacy C++ → Rust
rewrite scope" → `shekyld fee_policy_version daemon-side exposure`
(2026-04-25, post-Phase-0 land).

---

## 2026-04-25 — `monero-oxide` re-pin: split into Operation A (Phase 0) and Operation B (un-pin V3.1.x plan)

**Decision.** The vendor work on `monero-oxide` splits into two distinct
operations with different risk/value profiles, each scoped to a different
plan/phase:

- **Operation A — vendor-bump to fork tip.** Sync vendored
  `rust/shekyl-oxide/` from the current snapshot at `87acb57` to
  `Shekyl-Foundation/monero-oxide` `fcmp++` HEAD `3933664`. Five commits,
  none crypto-substantive except `182b648`'s base58 decoder hardening.
  Mechanical, cheap, unblocked. **Scoped into Phase 0 of the wallet
  rewrite plan as PR 0.6.**
- **Operation B — un-pin / fork-rebase against upstream.** Pick up the 40
  upstream commits since the 2025-11-22 merge base (cypherstack
  `cba7117`, Veridise `HelioseleneField::invert` cluster
  `00bafcf`/`af44fb4`/`f58f2a9`/`e5d533c`, missing
  `ConditionallySelectable` bound `0d6f5e8`, WCG library invariant fix
  `1ac294e`, plus the upstream restructure that split `rpc` into
  `interface`+`/daemon` and moved `fcmp++` into `ringct/`); decide which
  crates the Shekyl fork attributes, which return to upstream, which are
  dropped. **Scoped to a separate V3.1.x un-pin plan, NOT Phase 0 of the
  wallet rewrite.**

**Rationale.** The audit report
([`docs/MONERO_OXIDE_VENDOR_STATUS.md`](MONERO_OXIDE_VENDOR_STATUS.md))
identifies these as different operations and explicitly recommends
treating them differently. Conflating them is the trap.

The vendor-bump (Operation A) is mechanical, the audit calls it out as
"available and cheap," and doing the audit but not landing the available
bump leaves the vendored tree in a known-stale state for the duration of
Phase 1+ — exactly what Phase 0 exists to prevent. The only content
review needed is `182b648`'s base58 decoder change, which gets verified
against `shekyl-address`'s round-trip semantics. Half-day PR, single
commit, hard cost ceiling: if verification goes red, bail out and let
Phase 1 begin against the existing vendored tree.

The un-pin (Operation B) is genuinely a separate plan. The 40-commit
delta includes a path restructure that forces architectural decisions
about whether the Shekyl fork tracks upstream's layout going forward —
exactly the decision the un-pin plan exists to make. Picking up
substantive commits without picking up the restructure means
cherry-picking, conflict resolution, and per-commit review burden;
folding it into Phase 0 of the wallet rewrite breaks the "single
coherent thing per phase" principle and adds a separate failure mode the
rewrite doesn't need.

**The active correctness bug `00bafcf` (`HelioseleneField::invert`
Veridise edge case) does not change this assessment.** The bug exists
today on `dev`; Operation A doesn't fix it (only Operation B does); and
the wallet rewrite's Phase 1 API shape doesn't depend on which version
of `HelioseleneField::invert` is correct (the bug is below the wallet
stack's API surface). Phase 0 closing without picking up Operation B
leaves the world exactly as it currently is on this dimension. The fix
needs to land, but it needs to land in the un-pin plan, not in Phase 0
of the rewrite.

**Alternatives considered.**

- *Fold both operations into Phase 0.* Rejected: 40-commit upstream
  merge with substantive crypto changes adds review burden and
  failure-mode surface that the rewrite doesn't need; if the upstream
  merge goes wrong, Phase 1 is blocked on resolving that, not on Phase
  0's actual goals.
- *Defer both operations to V3.1.x.* Rejected: the vendor-bump is
  mechanical and cheap; deferring it leaves the vendored tree
  known-stale for the entire duration of Phase 1+. The point of doing
  the audit is to act on it where action is cheap.
- *Fold Operation A into PR 0.4 (the audit PR).* Rejected for review
  hygiene: the audit produces the recommendation; the bump executes it.
  Mixing recommendation and execution makes review harder and creates
  the wrong precedent for future audit-and-act cycles.

**Lifecycle.** Operation A's PR (0.6) lands as part of Phase 0. Once it
lands, this entry stands as the rationale for why a 40-commit upstream
delta did not also land. Operation B's un-pin plan, when it kicks off,
references this entry and the audit report as its input queue. The
half-day review gate's item 5 — "confirm whether un-merged-upstream
commits affect Phase 1 Wallet API shape" — is the explicit checkpoint
that determines whether Operation B can run in parallel with rewrite
Phases 1–3 (expected) or must precede Phase 1 (only if a public type
signature changes in a way the wallet would compose against).

**Cross-link.** PR 0.4 audit
[`docs/MONERO_OXIDE_VENDOR_STATUS.md`](MONERO_OXIDE_VENDOR_STATUS.md);
PR 0.6 vendor-bump in the rewrite plan
[`.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md`](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md);
un-pin follow-up
[`docs/FOLLOWUPS.md`](FOLLOWUPS.md) §"V3.1+ — Legacy C++ → Rust rewrite
scope" → `monero-oxide un-pin / fork-and-attribute / drop-unused-crates
(Operation B)`.

---

## 2026-04-25 — Phase 0 review-gate findings + PR 0.6 vendor-bump execution

**Decision.** Phase 0 of the V3 wallet rewrite is complete after PR 0.6.
The half-day review gate cleared all five items cleanly, no cross-cutting
locks were superseded, no un-merged upstream commit was found to affect
Phase 1's Wallet API shape, and the `87acb57` → `3933664` vendor-bump
turned out to be strictly metadata-only at the shekyl-core level. Phase 1
(Wallet API + cross-cutting locks codification) is unblocked.

**Review-gate findings (per the five-item checklist in the rewrite plan).**

1. **PR 0.4 vendor-status (`docs/MONERO_OXIDE_VENDOR_STATUS.md`).**
   Confirmed the Operation A / Operation B split is the correct
   decomposition. Operation A (5 commits, only `182b648` carries content
   delta) is cheap; Operation B (40 commits including the cypherstack
   audit response and the Veridise `HelioseleneField::invert` cluster) is
   genuinely a separate plan because of the upstream restructure
   decision it forces.

2. **PR 0.3 / 0.5 daemon-side findings
   (`docs/SHEKYLD_PREREQUISITES.md`).** Confirmed (a) regtest
   `--regtest --offline --fixed-difficulty 1 + generateblocks` is usable
   for Phase 6; (b) `get_fee_estimate` returns a positional 4-slot
   `fees` vector (no name-keyed buckets on the wire — wallet maps names
   to positions, see the "Fee priority on the daemon RPC" entry above);
   (c) `fee_policy_version` is absent on the daemon today and that's a
   V3.1 daemon follow-up, not a Phase 0 blocker — Phase 2a's wallet
   client treats the field as an `Option<u32>` so it absorbs the field
   gracefully when the daemon eventually carries it.

3. **`docs/FOLLOWUPS.md` V3.1+ rewrite interactions.** Confirmed the
   rewrite-interaction index table at the head of the section and the
   per-entry annotations. `wallet2.cpp` absorption, the `WalletPrefs`
   round-trip property test, and PQC Multisig V3.1 hardware-wallet
   integration are absorbed by the rewrite phases. `shekyl-cli`
   key-image binary export and `wallet_tools.cpp` mixin/decoy
   infrastructure close at Phase 5 (deletion). The
   `shekyl-daemon-rpc` staticlib `tracing::*` drop closes via Phase 1's
   logging deliverable picking up daemon-side `tracing-subscriber`
   initialization. Operation A closes here (PR 0.6); Operation B stays
   open as a V3.1.x peer plan.

4. **Cross-cutting locks confirmation.** All eleven locks (Tokio runtime,
   `thiserror` + typed enums, `tokio::sync::RwLock` discipline,
   `PendingTx` lifetime, network enum + safety constants, `{account,
   address}` subaddress hierarchy, refresh handle semantics, fee
   priority, structured `tracing::*` logging, KAT testing budget, and
   the decision-log itself) stand. The PR 0.3/0.5 audit findings refine
   the fee-priority lock — wallet-side mapping of name → position — but
   do not supersede it.

5. **Un-merged upstream commits and Phase 1 Wallet API shape.**
   Substantive upstream commits the fork is missing
   (`cba7117` cypherstack response, `00bafcf` HelioseleneField::invert,
   `0d6f5e8` ConditionallySelectable bound, `1ac294e` WCG invariant fix,
   `a5cc436` WCG sparse-BTreeMap representation, `7568518` lazy
   deserialization in SA+L proof, `8ff1f90` GBP optimization) all
   modify internal cryptographic primitives in `shekyl-oxide`'s
   `crypto/*` and `shekyl-oxide/fcmp/*` subtrees. None changes a public
   type signature in a way the wallet would compose against — `PendingTx`
   is a process-local opaque value, the SA+L proof bytes are an
   already-constructed wire payload, and FCMP++ membership-proof
   construction lives behind `shekyl-tx-builder`/`shekyl-proofs` not
   directly on the wallet API. Operation B can therefore proceed in
   parallel with rewrite Phases 1–3 rather than blocking them.

**PR 0.6 vendor-bump execution (Operation A).** The audit predicted the
bump would be "trivial" with one base58-content review. Execution made it
even simpler:

- The only files that changed in vendored path globs (`crypto/**` and
  `shekyl-oxide/**`) between `87acb57` and `3933664` are
  `shekyl-oxide/wallet/base58/src/{lib,tests}.rs`. The fork's
  `shekyl-oxide/wallet/` subtree is **not** vendored in
  `rust/shekyl-oxide/` of shekyl-core (per `60-no-monero-legacy.mdc`,
  Shekyl uses native Bech32m via `shekyl-address`, not the Monero-shaped
  `wallet/{address, base58}`).
- The umbrella `shekyl-oxide/Cargo.toml` is byte-identical between
  vendored and fork tip; `182b648`'s Cargo profile changes live in the
  fork's workspace-root `Cargo.toml`, which is also not vendored.
- Workspace grep for fork-base58 references
  (`monero_base58 | shekyl-oxide.*base58 | ::base58::`) finds zero
  matches across `rust/`. The base58 hardening is strictly more
  restrictive (`checked_add` + non-canonical encoding rejection) and
  would only ever return additional `None` values to a downstream
  consumer, never different `Some(_)` payloads.

**Net result.** PR 0.6 is metadata-only — it updates
`rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT` from
`87acb57e0c3935c8834c8a270bd3bdcbbe36bcde` to
`3933664d0851871c976f07298b862373d1c6fec0` and updates documentation. No
vendored source files change. Workspace verification per
`docs/SHEKYL_OXIDE_VENDORING.md`: `cargo build --locked -p shekyl-fcmp`
clean; `cargo test --locked --workspace` 900 passed, 0 failed, 6 ignored.

**Implication for future bumps.** The fork's `shekyl-oxide/wallet/`
subtree being non-vendored means a future bump that contains *only*
wallet-subtree changes is also metadata-only at the shekyl-core level
and can be turned around in minutes once the audit confirms which paths
actually changed.

**Cross-link.**
[`docs/MONERO_OXIDE_VENDOR_STATUS.md`](MONERO_OXIDE_VENDOR_STATUS.md)
§"PR 0.6 vendor-bump execution (2026-04-25)";
[`docs/CHANGELOG.md`](CHANGELOG.md) `[Unreleased]`/Changed entry for
PR 0.6;
[`.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md`](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md)
Phase 0 PR 0.6 deliverable.

---

## 2026-04-25 — `LocalLabel` / `SecretStr` typing for locally-sensitive UTF-8

**Decision.** Phase 1 (`shekyl-wallet-core` rewrite) introduces two
types in `shekyl-wallet-state` for every user-supplied UTF-8 string the
wallet *persists but never transmits* — address-book descriptions,
subaddress labels, transaction notes:

- **`LocalLabel(Zeroizing<String>)`** — owned wrapper. `Clone` and
  `Default` (the containing bookkeeping / tx-metadata blocks derive
  `Default`). **Not** `Copy`, **not** `Serialize`, **not**
  `Deserialize`. `Debug` and `Display` redact to
  `"<redacted N bytes>"` — length is leaked deliberately (it is
  always observable from the on-disk envelope's framing), bytes are
  not.
- **`SecretStr<'a>(&'a str)`** — borrowed, lifetime-tagged view
  returned by `LocalLabel::expose()`. Same redacting `Debug` /
  `Display`. Callers that genuinely need the underlying `&str` (e.g.
  to render in a TUI) call `SecretStr::as_str()` explicitly; the call
  site is the audit point.

Persistence goes through the explicit `serde_helpers::local_label`
adapter (`#[serde(with = "local_label")]`), which routes through
`LocalLabel::expose_for_disk()` — the only named, named accessor that
hands raw bytes to a serializer. Wire format is byte-identical to a
plain `String` (test
`serde_helpers::tests::local_label_postcard_wire_matches_plain_string`
pins this), so retyping a `String` field to `LocalLabel` does **not**
bump any block version.

**Rationale.** This is the type-layer realization of cross-cutting
lock 9 (logging — `tracing` with two-layer secret redaction). Locality
of UI metadata is a property the type system can enforce at compile
time rather than rely on developer discipline at every log statement.
The wallet2 lineage treated tx_notes / address-book descriptions /
subaddress labels as ordinary `String`, which meant any future
`info!(?wallet)` would leak them; the V3 wallet treats them as opaque
locally-zeroizing wrappers, and the only opt-out is a named accessor
the auditor can grep.

**Why value-typed `SecretStr<'a>` rather than the literal `&SecretStr`
shorthand the lock uses.** A DST newtype around `str` (the only way
to make `&SecretStr` work) requires a `unsafe { &*(s as *const str as
*const SecretStr) }` cast. The workspace forbids `unsafe_code` per
`#![deny(unsafe_code)]` on every crate and per the workspace's
top-level Rust policy. Both shapes deliver the same property
(callers cannot `format!("{secret}")` without redaction; callers
must explicitly call `as_str()` to inspect bytes); the value-typed
form is the safe-Rust-compatible realization.

**Why `Default` despite the construction-grep argument.** The
containing bookkeeping / tx-metadata blocks derive `Default` so the
orchestrator can build empty instances at create time without naming
every field; if `LocalLabel: !Default`, those derives break and every
field needs an explicit initializer. The doc-comment grep for "where
does an empty label appear?" routes through `LocalLabel::empty()` (an
explicit named constructor); `LocalLabel::default()` is a transparent
synonym.

**What this does NOT cover.** The retype of bookkeeping_block fields
(`SubaddressLabels::primary`, `SubaddressLabels::per_index`,
`AddressBookEntry::description`) and tx_meta_block fields
(`TxMetaBlock::tx_notes`) lands in subsequent commits. This entry pins
the type's shape so those retypes are mechanical. `TxMetaBlock::attributes`
(JSON-shaped UI prefs, e.g. `"display.theme" = "dark"`) is **not**
locally sensitive and stays `String` keyed → `String` valued.

**Cross-references.** Cross-cutting lock 9 (this file, "Wallet stack:
cross-cutting locks (Phase 0 review-gate decisions)" §9);
[plan §"Phase 1 deliverables"](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md);
new module `rust/shekyl-wallet-state/src/local_label.rs`; new adapter
`rust/shekyl-wallet-state/src/serde_helpers.rs::local_label`.

---

## 2026-04-25 — Per-domain `Wallet` error enums + sealed `WalletSignerKind`

**Decision.** Phase 1 lands the type-layer foundations of the
`shekyl-wallet-core::wallet` orchestrator without yet introducing the
`Wallet` struct. Three pieces ship in this commit:

1. **Per-domain error enums** in
   `rust/shekyl-wallet-core/src/wallet/error.rs`: `OpenError`,
   `RefreshError`, `SendError`, `PendingTxError`, `KeyError`,
   `IoError`, `TxError`. Each is closed (no `Other(String)` catch-all).
   The plan-locked variants are pinned by name:
   `OpenError::NetworkMismatch`,
   `OpenError::CapabilityMismatch`,
   `OpenError::OutstandingPendingTx`,
   `RefreshError::ConcurrentMutation`,
   `RefreshError::AlreadyRunning`,
   `RefreshError::Cancelled`,
   `PendingTxError::TooOld`,
   `PendingTxError::ChainStateChanged`,
   `PendingTxError::UnknownHandle`,
   `TxError::DaemonFeeUnreasonable`.
   `IoError` is intentionally distinct from `std::io::Error` because the
   wallet's IO surface includes daemon RPC, scanner, and ledger
   serialization — not just filesystem syscalls.
2. **`Network` re-export** from `shekyl_address::Network`. The plan's
   fourth variant (`Fakechain`) is **not** added in this commit; it
   requires a workspace-wide change (HRP tables, `NetworkSafetyConstants`,
   `DerivationNetwork`, wallet-file region-1 byte parse) that lands in a
   separate scoped commit on the same Phase 1 branch.
3. **`Capability` re-export** from `shekyl_wallet_file::Capability`.
   The plan refers to this concept as "`CapabilityMode`"; the canonical
   spelling already established in the wallet-file crate is the shorter
   `Capability`. One canonical name across the workspace, not an alias.
4. **Sealed `WalletSignerKind` trait** with `SoloSigner` ZST as the
   only implementer. V3.1 multisig will add `MultisigSigner<N, K>`
   behind the existing `multisig` Cargo feature.

**Rationale.** Cross-cutting lock 2 binds the per-domain error shape;
this commit is the type-system realization. Defining the variants now,
without method bodies, lets reviewers see the failure surface a
`Wallet` consumer will face before the lifecycle methods land. Closed
enums (no `Other(String)`) make the JSON-RPC error-code allocation in
`shekyl-wallet-rpc` a finite mapping rather than an open-ended one.

**`#[from]` deferred per-call-site.** This commit does not wire
`#[from]` impls for `shekyl_wallet_file::WalletFileError`,
`shekyl_crypto_pq::CryptoError`,
`shekyl_wallet_state::WalletLedgerError`, or
`shekyl_wallet_prefs::PrefsError`. Each `#[from]` lands alongside the
lifecycle / refresh / send commit whose `?` operator needs the
conversion, so an `#[from]` impl never exists without a caller. The
wallet-core crate's transitive dependency on
`shekyl-wallet-state` / `-prefs` / `-crypto-pq` is added when that
commit lands (this commit only adds `shekyl-address` and
`shekyl-wallet-file` for the re-exports above).

**Why a sealed trait, not an enum, for the signer dispatch.** An enum
forces every method that depends on signer kind to `match` at runtime,
producing unreachable arms in V3.0 (where only `SoloSigner` exists)
and reintroducing the runtime-mode-flag pattern the rewrite explicitly
rejects. A trait with associated items lets each kind name its own
associated types (e.g., the eventual `SignaturePayload`,
`SigningCeremony`) and lets the type system statically prove that solo
and multisig code paths never share a runtime branch. Sealing the
trait preserves the audit guarantee that no third signer kind appears
without a Decision Log entry.

**Cross-references.** Cross-cutting locks 2, 4, 5, 6, 7, 8 (this file,
"Wallet stack: cross-cutting locks (Phase 0 review-gate decisions)");
[plan §"Phase 1 deliverables"](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md);
new module `rust/shekyl-wallet-core/src/wallet/`.

---

## 2026-04-25 — `Wallet<S>` struct shape and accessor surface

**Decision.** The Phase 1 follow-up commit lands the `Wallet<S:
WalletSignerKind>` struct itself with its full dependency graph,
read-only accessor surface, and a thin `DaemonClient` wrapper around
`shekyl_simple_request_rpc::SimpleRequestRpc`. Six concrete sub-decisions
ship together, each binding for downstream code:

1. **Field set fixed at eight members.** `file: WalletFile`, `keys:
   AllKeysBlob`, `ledger: WalletLedger`, `prefs: WalletPrefs`, `daemon:
   DaemonClient`, `network: Network`, `capability: Capability`, plus
   `_signer: PhantomData<S>` for compile-time signer dispatch. No
   "miscellaneous state" bag, no `runtime_state: RuntimeWalletState`
   (the `RuntimeWalletState` audit decision lands in its own commit and
   currently leans toward folding into `WalletLedger`).
2. **`network` and `capability` are cached on the struct, not delegated
   to `WalletFile`.** The plan explicitly lists both as fields. The
   correctness argument is that `WalletFile`'s region 1 is write-once
   after `create` (only `change_password` rewraps the file_kek without
   touching the AAD bytes), so the cache cannot drift. The
   accessor-speed argument is that a `Wallet::network()` call on an
   `Arc<RwLock<Wallet>>` should not have to traverse the file handle's
   accessor chain.
3. **`Wallet<S>` does not implement `Drop`.** The two secret-bearing
   composed types — `AllKeysBlob` and `WalletFile` — each ship their
   own `Drop` that wipes the relevant material (Ed25519 / view scalars,
   ML-KEM-DK, `file_kek`, advisory lock release). A wrapper `Drop` here
   would risk shadowing the inner ones at compile time without changing
   behavior at run time, and adds an audit point with no security
   value. Composing types that already wipe correctly is sound; this
   commit relies on that contract being upheld by the inner types
   (which it is, per their own audit-log entries).
4. **`Wallet::keys()` is `pub(crate)`, not `pub`.** Phase 2 sign /
   proof code paths inside `shekyl-wallet-core` go through this
   accessor; the returned `&AllKeysBlob` reference must not escape the
   crate. Phase 2 will add dedicated method-level surfaces
   (`sign_transfer`, `tx_proof`, `reserve_proof`) that take borrowed
   inputs and return finished artifacts, so external call sites
   (`shekyl-cli`, `shekyl-wallet-rpc`) never need to borrow the keys
   directly. Allowing `pub` access would re-introduce the
   wallet2-shaped pattern of "give me the keys and I'll do the math
   myself" that the rewrite explicitly rejects.
5. **`DaemonClient` is a thin `pub struct` wrapper, not a `pub use`
   re-export.** Three independently sufficient reasons:
   (a) insulates `Wallet`'s public API from the transport choice — the
   `Wallet::daemon()` accessor returns a stable type, so a future
   transport swap (UDS, gRPC, in-process test fake) does not change
   the wallet-level signature; (b) gives Phase 2a a single audited
   site for the `get_info` network-mismatch check, the
   `get_fee_estimates` fee-priority resolution, and the daemon-bound
   tracing spans — adding these to a `pub use` re-export is impossible;
   (c) keeps the cross-cutting lock 1 contract (caller-provided
   multi-threaded `tokio` runtime) localized to one wrapper rather
   than radiating through the wallet API.
6. **`shekyl-crypto-pq` becomes a non-optional dependency of
   `shekyl-wallet-core`.** Previously the dep was gated behind the
   `multisig` feature flag (which still exists for the FROST scaffold);
   with `keys: AllKeysBlob` now on the struct, the dep is required
   regardless of feature. The `multisig` feature retains its remaining
   gates (`shekyl-fcmp/multisig`, `modular-frost`, `chacha20poly1305`,
   `hkdf`, `sha2`, `serde`, `serde_json`, `zeroize`, `hex`).

**Rationale.** This commit operationalizes the cross-cutting locks
that bind on the *type shape* of the orchestrator (lock 1 caller-async,
lock 3 `&self` / `&mut self` discipline, lock 4 `PendingTx` lifetime
through ledger-resident reservations) without yet committing to the
behavioral shape of the lifecycle methods (`create`, `open_full`,
`open_view_only`, `open_hardware_offload`, `change_password`, `close`).
Reviewers see the failure-surface (per-domain error enums, previous
commit) and the success-shape (this commit, struct fields and
accessors) before the methods land that connect the two.

**Reservation tracker: runtime-only on `Wallet`, never persisted.**
The `pending_tx` follow-up commit (2026-04-26) refines cross-cutting
lock 4 from "ledger-resident reservations" to "`Wallet`-resident
runtime-only reservations." The reasoning: `PendingTx` is already
process-local (this entry's section "PendingTx lifecycle" above), and
`Wallet::close` errors with [`OpenError::OutstandingPendingTx`] when
any reservation is in flight. The only path that would persist a
reservation across a wallet-close boundary is a process crash between
`build_pending_tx` and `submit_pending_tx`/`discard_pending_tx` — and
the correct behavior on that path is "the reservation is gone, the
outputs are spendable again, the user re-runs build" because the tx
never broadcast. Persisting reservations would force a reconciliation
path on next open with no in-memory `PendingTx` handle to surface them
through, leaking handles whose state machine has no caller.

The reservation tracker therefore lives on `Wallet<S>` as a runtime-
only `BTreeMap<ReservationId, Reservation>` field alongside
`indexes: LedgerIndexes` (which is also runtime-only and rebuilt at
open). `BOOKKEEPING_BLOCK_VERSION` does **not** bump for this commit;
the bookkeeping block stays scoped to subaddress registry, labels,
and address book.

**What this entry's earlier paragraph said and why it's wrong.** The
original wording was "the in-flight transaction reservation ledger
lives in `WalletLedger`'s bookkeeping block, not on `Wallet`." That
was inherited from cross-cutting lock 4's draft phrasing, which
predated the decision to make `Wallet::close` error on outstanding
pending. Once close errors, the persistence rationale evaporates; the
present paragraph supersedes it.

**What is still locked.** Cross-cutting lock 4's behavioral shape is
unchanged: build reserves, discard releases, submit consumes, close
errors with outstanding. Only the storage location moved from
"persisted bookkeeping block" to "runtime field on `Wallet`." Cross-
cutting lock 7 (cancel-on-drop refresh handle returned by `refresh`,
not stored on `Wallet`) is unaffected.

**Why `PhantomData<S>` and not a trait-object signer.** The compile-
time dispatch promised by `Wallet<S: WalletSignerKind>` requires that
`S` appear in the type and method signatures, but the actual signer
*state* (for `SoloSigner`, the spend secret) is already on `keys:
AllKeysBlob`. A `PhantomData<S>` field carries the type parameter
without storing duplicate signer-kind state. V3.1's `MultisigSigner<N,
K>` will add a sibling field (`multisig_state: MultisigContext<N, K>`)
gated on the `multisig` Cargo feature; existing `SoloSigner` call sites
will not need source changes.

**Cross-references.** Cross-cutting locks 1, 3, 4 (this file, "Wallet
stack: cross-cutting locks");
[plan §"Phase 1 — Wallet domain model" → "What's a `Wallet`?"](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md);
prior entry "Per-domain `Wallet` error enums + sealed
`WalletSignerKind`" (immediately above) for the type-layer foundations
this builds on.

---

## 2026-04-25 — `RuntimeWalletState` audit: full fold, derived indexes rebuilt at open

**Decision.** `RuntimeWalletState` (`rust/shekyl-wallet-state/src/runtime_state.rs`)
ceases to exist as a named type. The fields it carries beyond the
persisted `WalletLedger` split into two groups:

*Already covered by the on-disk bundle* (no change needed; just stop
duplicating them):
- `transfers: Vec<TransferDetails>` → `WalletLedger.ledger.transfers`
- `synced_height: u64` → `WalletLedger.ledger.tip.synced_height`
- `blockchain: Vec<(u64, [u8; 32])>` → `WalletLedger.ledger.reorg_blocks.blocks`

*Runtime-only state derived from chain replay* (the new
`LedgerIndexes` home):
- `key_images: HashMap<[u8; 32], usize>` — lookup index from
  key-image bytes to `LedgerBlock.transfers` index.
- `pub_keys: HashMap<[u8; 32], usize>` — lookup index from output
  public-key bytes to `LedgerBlock.transfers` index.
- `staker_pool: StakerPoolState` — aggregated stake-tier accrual
  state. `LEDGER_BLOCK_VERSION = 1` deliberately omits its
  persistence per the staking design notes; it is rebuilt by
  scanner replay just like the lookup indexes.

The two-group split matters because the unifying principle for
`LedgerIndexes` is **"computed at scan time, not persisted, rebuilt
on every open"** — the lookup indexes happen to be hash maps and
`staker_pool` happens to be aggregated state, but both are
reconstructible from `LedgerBlock` plus daemon block replay. A
field that needs persistence is a `LedgerBlock` change (and bumps
`LEDGER_BLOCK_VERSION`), not a `LedgerIndexes` change.

The fold:

1. Promote the runtime-only group into a new `pub struct LedgerIndexes`
   that **lives on `Wallet`**, not on `WalletLedger`. The struct is
   not `Serialize` / `Deserialize`. It is rebuilt from
   `WalletLedger.ledger.transfers` (plus daemon replay for
   `staker_pool` accruals) at `Wallet::open*` time, and maintained
   in lock-step with mutations through a single mutation-helper
   surface that wraps every ledger write.
2. The block-processing methods (`ingest_block`, `mark_spent`,
   `unmark_spent`, `detect_spends`, `set_key_image`, `handle_reorg`,
   `insert_accrual`, `freeze_by_key_image`, `thaw_by_key_image`)
   move from `RuntimeWalletState` to `LedgerIndexes`, taking
   `&mut self, ledger: &mut LedgerBlock, …` so a single call updates
   both ledger state and indexes atomically. Methods that don't
   touch indexes (`freeze`, `thaw`, `set_staking_info`,
   `update_claim_watermark`) move to inherent methods on
   `LedgerBlock` and don't borrow `LedgerIndexes` at all.
3. Read-only query methods (`unspent_transfers`, `staked_outputs`,
   `matured_staked_outputs`, `locked_staked_outputs`,
   `claimable_outputs`, `unstakeable_outputs`, `spendable_outputs`,
   `block_hash_at`, `height`, `transfer_count`) move to inherent
   methods on `LedgerBlock`. The single read-only query that needs
   indexes (`staker_pool`) is an accessor on `LedgerIndexes`.
4. The `pub use crate::runtime_state::RuntimeWalletState as WalletState`
   transitional alias and the `wallet_state` re-export shim in
   `shekyl-scanner` are deleted; nothing outside the workspace
   depends on the old name.
5. `runtime_state.rs` is deleted as a module; its inherent-test
   coverage is absorbed into `ledger_indexes::tests`.

**Rationale.** Two principles converge on this shape:

- **Indexes are derivable from authoritative state, so derived state
  shouldn't be persisted.** Putting `key_images` / `pub_keys` into
  `LedgerBlock` would require a schema bump every time the index
  type changed (e.g., switching `HashMap` to `IntMap`, adding a
  secondary index from `block_height` to `transfer_idx`). Rebuilding
  at open keeps the indexes a private implementation detail of
  `Wallet` rather than part of the on-disk contract that
  `BOOKKEEPING_BLOCK_VERSION` has to defend.
- **`Wallet`'s `&self` / `&mut self` discipline (cross-cutting lock
  3) is harder to honor when the ledger and its indexes are
  separable.** With a `RuntimeWalletState` value that wraps both,
  callers have to choose whether `process_block` takes
  `&mut RuntimeWalletState` or two `&mut` parameters; the former
  hides the fact that the ledger is mutating, and the latter
  splatters the borrow across signatures. Folding both into a single
  `Wallet`-owned representation pushes the locking decision to one
  site — `Wallet`'s outer `&mut self` — and the mutation helpers
  become free of locking concerns.

**Rejected alternatives.**

- "Promote the indexes into `LedgerBlock` so they round-trip through
  serialization." Makes deserialization quadratic in the number of
  enotes (every load reads the ledger then reads the indexes built
  from it, forcing the deserializer to either re-derive and verify
  the persisted indexes match — quadratic — or trust the on-disk
  bytes blindly — corruption surface). Open-time rebuild is linear,
  cache-friendly, and verifies the ledger is internally consistent
  as a side effect.
- "Keep `RuntimeWalletState` as a separate value owned by `Wallet`,
  passed `&mut` into block-processing methods." Leaks the
  index-rebuilding contract into `Wallet`'s public surface (callers
  would see the type in error messages, in `Debug`-printed
  `Wallet` output, in stack traces). A `pub(crate)` struct that
  never escapes the crate is the right scope.
- "Put both `WalletLedger` and the runtime indexes inside a single
  `pub struct WalletState` that `Wallet` owns." Re-introduces the
  exact shape we're folding away, just renamed. The fold's value is
  in the elimination of the wrapper, not in its renaming.

**Consequence.**

- `shekyl-wallet-state` no longer exposes a "current state of the
  wallet" type — it exposes the on-disk `WalletLedger` plus its
  block / sub-block types. `Wallet` (in `shekyl-wallet-core`) is the
  only owner of the runtime indexes that wrap the ledger.
- `runtime_state::tests::*` and any external doctests that named
  `RuntimeWalletState` are migrated to `wallet/` and renamed before
  this entry's commit lands; the rename is a hard break, not a
  deprecation, because there are no users.
- The `WalletLedger`'s schema is unchanged by this fold —
  `BOOKKEEPING_BLOCK_VERSION` does not bump. Schema fixtures stay
  byte-identical.
- The `network` field on `RuntimeWalletState` (currently used by
  `runtime_state::filter`) moves to `Wallet`'s already-cached
  `network: Network` accessor (Decision Log entry "Wallet<S> struct
  shape and accessor surface" sub-decision 2). Filter helpers that
  needed `network` re-fetch it from `&Wallet` instead of from a
  ledger-attached field.

**Reference.** Cross-cutting locks 3 (writer-preferred `&mut self`
mutation discipline) and 4 (`Wallet`-resident runtime-only
reservations; see the "Reservation tracker" sub-section of the
"Wallet<S> struct shape and accessor surface" entry above for the
2026-04-26 narrowing of lock 4 from "ledger-resident" to
"runtime-only");`Wallet<S>` struct entry sub-decision 1 (no
`runtime_state` field on `Wallet`); todo `runtime_state_audit` in the
Phase 1 task list.

---

## 2026-04-25 — `tx_keys` storage: persist in `TxMetaBlock`, never re-derived

**Decision.** Per-transaction secret keys (the spend-randomness
scalar `r` and any per-output additional keys) are persisted by the
wallet, keyed by transaction hash, in
`TxMetaBlock::tx_keys: BTreeMap<[u8; 32], TxSecretKeys>` where
`TxSecretKeys { primary: TxSecretKey, additional: Vec<TxSecretKey> }`.
The schema is already shipped (`tx_meta_block.rs::TxMetaBlock` line
174 at the time of this entry); this Decision Log entry locks the
shape and the rule that no `Wallet` operation re-derives `tx_keys`
from any other state.

**Rationale.** Three independent properties argue for persistence:

1. **`tx_proof` and `reserve_proof` regeneration require the
   per-tx randomness.** A user proving "I sent this transaction" or
   "I control these enotes" against a recipient or auditor weeks
   later must reconstruct the same Schnorr-style proof the original
   transaction emitted. The proof binds to the per-tx secret, which
   was generated at build time and committed into the transaction
   bytes only as a public commitment. Without the secret, the proof
   cannot be re-emitted; without re-emitting, the user cannot prove
   anything about the transaction post-hoc.
2. **The secret cannot be re-derived from ledger state.** Unlike
   `key_images` or output `pub_keys`, the per-tx randomness is
   sampled at build time from the OS RNG; there is no
   wallet-key-plus-tx-input relation that recovers it. Persistence
   is the only mechanism.
3. **The size cost is negligible.** Each `TxSecretKey` is 32 bytes;
   `TxSecretKeys` adds a `Vec` length plus per-output entries (one
   per non-change output, capped by transaction-size limits at a
   few hundred outputs in pathological cases). Even a heavy power
   user with thousands of sent transactions accrues a few megabytes
   of `tx_keys` storage over a wallet's lifetime — orders of
   magnitude less than the `transfers` table itself.

**Rejected alternatives.**

- "Don't persist; require the user to re-key the transaction from
  recipient-supplied data when they need a proof." Recipient
  cooperation is exactly what `tx_proof` exists to remove — the
  proof is the wallet's unilateral attestation. Re-keying defeats
  the feature.
- "Persist only the primary key, derive `additional` from the
  recipient address list." `additional` keys are emitted on a
  per-output basis with values that depend on per-output randomness;
  there is no closed-form derivation from the recipient list alone.
  The `additional: Vec<TxSecretKey>` shape is load-bearing.
- "Encrypt the `tx_keys` map with a key separate from the file_kek
  so a memory dump of the open wallet doesn't expose them." The
  whole `WalletLedger` is encrypted at rest under the file_kek
  already; in-memory exposure of `tx_keys` while the wallet is open
  is the same threat surface as in-memory exposure of every other
  ledger field. A second layer adds complexity without changing the
  threat model.

**Consequence.**

- `Wallet::tx_proof(txid, ...)` and `Wallet::reserve_proof(...)`
  (Phase 2 deliverables) read `tx_keys` from the in-memory ledger
  by `txid` lookup; missing-entry is a typed
  `ProofError::TxKeyNotPersisted { txid }` rather than a re-derive
  attempt.
- The `Wallet::send` / `submit_pending_tx` path writes `tx_keys`
  into `TxMetaBlock` at submit time, before returning the
  `TxHash` to the caller. A submit that fails before write is a
  visible failure (the tx is not in the wallet's record), not a
  silent loss.
- The `BookkeepingBlock` / `TxMetaBlock` separation already in
  schema means `tx_keys` does not bloat the hot bookkeeping read
  path — only operations that explicitly touch tx-meta state
  (proof emission, note display) deserialize this block.
- `tx_keys` are `LocalLabel`-class secret-bearing values for
  `Debug` purposes (32-byte scalar bytes, not free-form UTF-8) but
  use the existing `TxSecretKey` type's redacting `Debug` impl
  (already in place at the time of this entry). This entry does
  not mandate further redaction work.

**Reference.** `rust/shekyl-wallet-state/src/tx_meta_block.rs`
(`TxMetaBlock::tx_keys` field, `TxSecretKeys` definition);
`rust/shekyl-wallet-state/src/invariants.rs` (`tx_keys` invariants);
Phase 2 deliverables for `tx_proof` / `reserve_proof` will close
this entry by realization.

---

## 2026-04-25 — Daemon-side `tracing` install: `shekyl_log_install_tracing_forwarder` under `shekyl-logging::ffi`

**Decision.** The Phase 1 logging deliverable closes the V3.2
follow-up *"`shekyl-daemon-rpc` staticlib: `tracing::*` calls
silently dropped"* (`docs/FOLLOWUPS.md`) by absorption, with the
following concrete shape:

- A new C-ABI export ships under `shekyl-logging::ffi`, **not**
  under `shekyl-daemon-rpc::ffi` and **not** as a fresh
  `shekyl_daemon_rpc_*` symbol. Name and signature:

  ```rust
  /// Install a `tracing::Subscriber` that forwards every event
  /// emitted from Rust staticlibs (currently `shekyl-daemon-rpc`,
  /// future Rust crates linked into C/C++ binaries) into the
  /// `shekyl-logging` subscriber configured by the most recent
  /// `shekyl_log_init_*` call. Idempotent: a second call after a
  /// successful first returns `SHEKYL_LOG_ERR_ALREADY_INSTALLED`.
  ///
  /// # Returns
  /// - `0` on first successful install.
  /// - non-zero `shekyl-logging` error code otherwise (see
  ///   `shekyl_log.h` for the table).
  ///
  /// # Safety
  /// Must be called after `shekyl_log_init_stderr` /
  /// `shekyl_log_init_file` has succeeded; calling before yields
  /// `SHEKYL_LOG_ERR_NOT_INITIALIZED`.
  #[no_mangle]
  pub unsafe extern "C" fn shekyl_log_install_tracing_forwarder() -> i32;
  ```

- The C++ daemon entry point (`src/daemon/main.cpp` /
  `src/shekyld_main.cpp` — exact site is implementation, not
  decision) calls this after `mlog_configure` and after
  `shekyl_log_init_*` has run. The C++ binary owns the call
  ordering; the Rust side is purely the forwarder install.
- `shekyl-daemon-rpc` keeps its existing `tracing::debug!` /
  `tracing::error!` / `tracing::span!` call sites — no
  rewrite to `shekyl_log_emit`. The forwarder makes them route
  through `shekyl-logging` automatically.

**Rationale.** Five constraints land this shape:

1. **The export lives in `shekyl-logging` because the
   subscriber it installs forwards into `shekyl-logging`.** The
   logging bridge is the right home for the symbol that bridges.
   A `shekyl_daemon_rpc_*` name in the same C namespace as
   `shekyl_log_*` is a smell — both prefixes claim to own
   logging, when only one does.
2. **The `shekyl_log_*` prefix matches the existing init pattern.**
   `shekyl_log_init_stderr` / `shekyl_log_init_file` /
   `shekyl_log_shutdown` / `shekyl_log_set_level` /
   `shekyl_log_emit` already form the surface; this is one more
   verb in the same family.
3. **The daemon-rpc crate is not the only consumer.** Future
   Rust crates linked as C-callable staticlibs into C/C++ binaries
   (e.g., a Rust scanner staticlib for the C++ wallet1 archive
   tooling that is being deleted in Phase 5 and may be re-introduced
   in C++-on-the-cli mode for V3.2) will need the same
   forwarder. A daemon-rpc-named symbol fits one consumer; a
   logging-named symbol fits all of them.
4. **Tracing-call rewrite is more invasive than subscriber
   install.** Rewriting `tracing::debug!(?response, "rpc");` into
   `shekyl_log_emit(level, target, format!(...).as_ptr(), ...)`
   is per-call-site work, loses structured-field metadata, and
   violates the cross-cutting lock that names `tracing` (not
   `shekyl_log_emit`) as the substrate inside Rust crates. The
   forwarder install is one C-callable function and zero call-site
   changes.
5. **Idempotence is required for daemon hot-reload.** `shekyld`
   may re-run `mlog_configure` on `SIGHUP`-style signal handling;
   the forwarder must not double-install (which would either panic
   on the global subscriber slot or silently leave the previous
   forwarder in place). A typed `ALREADY_INSTALLED` return lets
   the C++ side decide whether to treat that as success or as a
   reconfigure error.

**Rejected alternatives.**

- **Drop `shekyl-daemon-rpc`'s `tracing::*` calls entirely.**
  FOLLOWUPS Option 2 from the original V3.2 entry. Rejected per
  rationale #4 above: per-call-site rewrite, loss of structured
  fields, violation of the cross-cutting `tracing`-substrate lock.
- **Ship the export as `shekyl_daemon_rpc_init_logging` under
  `shekyl-daemon-rpc::ffi`.** FOLLOWUPS Option 1 (literal). Naming
  ties the symbol to one consumer; locality (the install lives
  next to the daemon-rpc crate) is offset by the symbol-namespace
  clash with `shekyl_log_*`.
- **Wire `tracing-subscriber::set_global_default` from inside
  the daemon-rpc staticlib's `lib.rs` constructor.** Constructors
  in static-lib Rust code don't reliably run before the C++
  binary's `main`; some platforms order them, some don't. Explicit
  C-callable install eliminates the ordering question.

**Consequence.**

- The FOLLOWUPS V3.2 entry *"`shekyl-daemon-rpc` staticlib:
  `tracing::*` calls silently dropped"* closes by absorption
  when this commit lands, the same way that earlier entries
  closed by absorption into Phase 1 (line 391 of
  `docs/FOLLOWUPS.md`'s status table marks it absorbed already;
  the substantive close is in this Decision Log entry).
- The `shekyl-logging` crate gains a new error code
  `SHEKYL_LOG_ERR_ALREADY_INSTALLED` (or analogous; final naming
  is implementation-trivial) and a new error code
  `SHEKYL_LOG_ERR_NOT_INITIALIZED`. Both land in
  `rust/shekyl-logging/src/ffi.rs`'s error-code table alongside
  the existing entries.
- The `shekyld` C++ build gains one new call site post-
  `mlog_configure`. No other C++ change is required.
- Rust binaries (`shekyl-cli`, `shekyl-wallet-rpc`, `shekyld-rust`
  if it ever exists) **do not** call this export — they call
  `shekyl-logging`'s native Rust subscriber-install API, which
  already configures the `tracing` global default. The export is
  exclusively for C/C++ binaries linking Rust staticlibs.

**Reference.** `docs/FOLLOWUPS.md` *"`shekyl-daemon-rpc` staticlib"*
entry (V3.2 → Phase 1 absorbed); `rust/shekyl-logging/src/ffi.rs`
(home for the new export); `rust/shekyl-daemon-rpc/src/`'s existing
`tracing::*` call sites (zero changes required); cross-cutting
lock 9 (logging substrate is `tracing`).

---

## 2026-04-25 — Phase 5 pre-emption rule + first application (`wallet_ledger_ffi.rs`)

**Decision.** Individual items from the Phase 5 deletion inventory may
be deleted before Phase 5 lands when their callers are conclusively
gone. The first application: `rust/shekyl-ffi/src/wallet_ledger_ffi.rs`
and the corresponding `shekyl_ffi.h` typed-per-block ledger section
were deleted on 2026-04-25 during the Phase 1 `primitives` task,
immediately after the `SubaddressIndex` flatten commit confirmed zero
`.cpp` / `.cc` / `.hpp` callers of any export from that file. The
deletion commit's message body carries the grep evidence; the Phase 5
commit's deletion inventory drops the now-deleted file from its
enumeration (`docs/FOLLOWUPS.md` — *wallet2.cpp absorption* entry,
sub-bullet *"Phase 5 inventory pre-emptions"*).

**The rule.** Pre-empting an individual Phase 5 deletion item is
acceptable when *all three* hold:

1. **Zero current callers.** `git grep` against `*.cpp`, `*.cc`,
   `*.h`, `*.hpp` returns no consumers outside the file itself
   (the Rust file's own definitions and its `shekyl_ffi.h` mirror
   prototypes do not count as callers).
2. **Evidence in the commit message body.** The exact grep commands
   and their (empty or self-only) output appear in the commit message
   body of the pre-empting commit. "I checked, it's empty" is not
   enough — reviewers must be able to reproduce the check from the
   durable git record, not from a PR description that disappears
   once the PR is merged.
3. **Atomic FOLLOWUPS / Phase-5-inventory update in the same
   commit.** The Phase 5 deletion list in `docs/FOLLOWUPS.md` (and
   any other inventory document) drops the pre-empted item, with a
   pointer back to the pre-empting commit. Without this step, Phase
   5 lands and someone tries to delete a file that no longer exists,
   then has to reconstruct what happened from git archaeology.

**Pre-empting items with surviving callers is not acceptable**, even
when the deletion looks easy. The Phase 5 mass-deletion exists
precisely so the audit surface for individual surfaces stays
predictable; an early deletion that orphans a caller dilutes the
audit by spreading the failure mode across multiple commits.

**Rationale.** Two pressures argue for pre-emption when the grep is
conclusive:

- The deleted surface is part of the `shekyl_wallet_*` C-ABI
  inventory the prior decision-log entry
  ("Phase 5 deletion scope: includes Rust FFI surfaces consumed
  only by C++") already binds for deletion. Preserving it for an
  unbounded period purely for inventory-symmetry trades real
  maintenance overhead (lint debt, dependency churn, doc references
  to deleted concepts) for a procedural neatness that does not
  affect correctness.
- The "while we're here is the enemy" rule (`15-deletion-and-debt.mdc`)
  is honored by *splitting* the pre-emption into its own commit, not
  by deferring the deletion. The first commit ships the in-scope
  feature work (rename / migration / type change) without the
  deletion; the immediate follow-up commit ships the deletion alone,
  one concern per commit, each bisectable.

**Rejected alternatives.**

- "Always wait for Phase 5." Carries dead surface forward for the
  entire rewrite window; produces a Phase 5 commit whose deletion
  inventory padding makes review slower, not faster.
- "Delete the dead surface in the same commit as the in-scope feature
  change." Conflates concerns; reviewer cannot bisect a regression
  in one half without unwinding the other. The two-commit shape
  preserves bisectability without preserving dead code.

**Consequence.** The Phase 5 commit's PR description names the
pre-empted items explicitly so the cumulative deletion ledger across
the rewrite is reconstructable from `git log` alone. A reviewer six
months from now should be able to type
`git log --grep="Phase 5 pre-emption"` and recover the full set of
deletions that landed early.

**Reference.** Commit message body of the deletion commit
immediately following the `SubaddressIndex` flatten commit
(2026-04-25) for the grep evidence; `docs/CHANGELOG.md`
`[Unreleased]` *Removed* entry for the human-readable summary.

---

## 2026-04-26 — `Wallet<S>` lifecycle: capability scoping for V3.0

**Decision.** The `shekyl-wallet-core` `Wallet<S>` lifecycle entry
points (`Wallet::create`, `Wallet::open_full`, `Wallet::open_view_only`,
`Wallet::open_hardware_offload`, `Wallet::change_password`,
`Wallet::close`) ship in V3.0 with full bodies for the FULL capability
path (`create` / `open_full` / `change_password` / `close`) and as
**signature-only stubs** for the ViewOnly and HardwareOffload paths
(`open_view_only` / `open_hardware_offload`). The stubs return a
single dedicated error variant
`OpenError::CapabilityNotYetImplemented { capability }`.

**Rationale.** The lifecycle commit's external dependencies are
asymmetric:

- `Wallet::open_full` composes `WalletFile::open`,
  `WalletFile::extract_rederivation_inputs`, the existing
  `shekyl-crypto-pq::account::rederive_account` (which produces a
  full `AllKeysBlob` with `spend_sk`, `view_sk`, `ml_kem_dk`, and
  every public-key field), `WalletFile::load_prefs`, and
  `LedgerIndexes::rebuild_from_ledger`. Every dependency is locked
  and on-disk-tested.
- `Wallet::open_view_only` and `Wallet::open_hardware_offload`
  additionally require `shekyl-crypto-pq` `AllKeysBlob` constructors
  that omit `spend_sk` / `ml_kem_dk` (view-only) or retain a device
  descriptor (hardware-offload). Those constructors are not yet
  written. Implementing them inside the lifecycle commit would fold
  three crates' worth of new API surface into a single PR.

The signature-only-stub shape keeps the lifecycle commit reviewable
in one bisectable diff while locking the public API for view-only
and hardware-offload paths. Call-site code (CLI, RPC, GUI) compiles
against the V3.0 surface and gets real bodies in a V3.0 follow-up
commit without any signature change.

**Stub error variant.** `OpenError::CapabilityNotYetImplemented` is
explicitly transient. It carries a deletion-target prose comment in
[`rust/shekyl-wallet-core/src/wallet/error.rs`](../rust/shekyl-wallet-core/src/wallet/error.rs)
naming `docs/FOLLOWUPS.md` *V3.0 → "View/HW lifecycle bodies in
`shekyl-wallet-core`"* as the deletion gate. When the constructors
land and the stub bodies are filled in, the variant is removed in
the same commit. Per `15-deletion-and-debt.mdc` ("Default: delete"),
the variant has no permanent home.

**Rejected alternatives.**

- *Defer all view-only and hardware-offload signatures to a later
  commit.* Forces every lifecycle caller (CLI / RPC / GUI / docs) to
  re-route once the signatures land. The cost of locking three
  signatures now is nil; the cost of re-routing every caller later
  is real.
- *Inline the missing `AllKeysBlob` constructors into the lifecycle
  commit.* Triples the diff size, mixes
  `shekyl-crypto-pq` and `shekyl-wallet-core` review concerns, and
  is the kind of commit that gets reviewed by nobody once it crosses
  ~800 lines.
- *Return `unimplemented!()` from the stubs.* Crashes the process
  rather than returning a typed error; downstream code cannot match
  on it. The variant is small, typed, and has an explicit deletion
  gate; an `unimplemented!()` panic is a regression in error
  posture.

**Reference.** Lifecycle commit (this commit) and the corresponding
plan `.cursor/plans/scope_211d438b.plan.md`.

---

## 2026-04-26 — `Wallet::open_full`: lost-state surfacing via typed `OpenedWallet` sum

**Decision.** `Wallet::open_full` returns `OpenedWallet<SoloSigner>`
rather than `Wallet<SoloSigner>`. The enum has two variants:

```rust
pub enum OpenedWallet<S: WalletSignerKind> {
    Loaded(Wallet<S>),
    Restored { wallet: Wallet<S>, from_height: u64 },
}
```

`Loaded` indicates the persisted ledger file was present and decoded
cleanly. `Restored { wallet, from_height }` indicates the keys file
was intact but the ledger file was missing or unreadable; the wallet
was reconstructed against an empty ledger anchored at
`from_height = restore_height_hint` (widened to `u64`), and the
caller must drive a refresh to restore state and `save_state` the
rebuilt ledger.

**Rationale.** The "lost-state" path is a real failure mode that
needs to be surfaced explicitly to the UI: a user whose
`<base>.wallet` file has been corrupted, deleted, or is on a
filesystem that lost the file across a crash needs to see "your
wallet state was rebuilt; resync from height N" rather than silently
opening a wallet whose balance reads zero. A flat
`Result<Wallet<S>, OpenError>` cannot carry the recovery signal:
either every successful return looks identical (silent rebuild,
worst case) or the recovery hint becomes a side channel (logged-only
warning, fragile).

A typed sum forces the caller to handle the recovery case at the
type level. The variant names carry meaning at the call site that
`(wallet, Option<u64>)` does not: "loaded" and "restored" are the
two product states, and the call site code reads as the operator
documentation.

**Rejected alternatives.**

- *`Result<(Wallet<S>, Option<RecoveryNotice>), OpenError>` tuple.*
  Admits `(wallet, None)` as the success-path representation when
  the success path is "loaded" specifically. The variant
  representation is structurally stronger than the tuple-with-Option
  alternative.
- *Logged-only signal, flat `Wallet<S>` return.* Loses the signal in
  any UI flow that doesn't surface log lines. The recovery
  notification belongs in the type, not in the trace stream.
- *Unconditional `Restored` variant with `from_height = 0` for the
  loaded case.* Conflates two distinct states; introduces an
  invariant ("`from_height = 0` means loaded, otherwise restored")
  that the type system cannot enforce.

**Reference.** Lifecycle commit (this commit). The pattern is reused
when `Wallet::refresh()` and `Wallet::apply_scan_result` land — a
refresh that runs against a `Restored { from_height }` wallet drives
the resync from `from_height` rather than from `synced_height`,
which would otherwise be 0.

---

## 2026-04-26 — Wallet authentication: V3.0 password-only; MFA is V3.1 via format-version bump

**Decision.** V3.0 ships the wallet file envelope with **password-only**
authentication: the file KEK is derived from `Argon2id(password,
wrap_salt)` and nothing else. MFA / hardware-token integration is
**V3.1** scope, gated on a wallet file format-version bump. V3.0
does not reserve fields for MFA. The lifecycle entry points take a
forward-compatible `Credentials<'_>` parameter so the V3.1 addition
is non-breaking at the API layer.

**Rationale.** Two pressures argued against folding MFA into V3.0:

- The threat model for hardware-token integration deserves an
  independent design cycle. Getting recovery right (token loss
  scenarios, BIP-39 seed-phrase fallback, optional multi-token
  enrollment) matters more than getting MFA shipped fast. A wallet
  that requires a hardware token but loses funds when the token is
  lost is worse than a wallet with no hardware token.
- The wallet file format already supports forward evolution via the
  `wrap_count` reserved byte and the
  `CAPABILITY_RESERVED_MULTISIG = 0x04` placeholder documented in
  [`docs/WALLET_FILE_FORMAT_V1.md`](WALLET_FILE_FORMAT_V1.md) §1
  and §3. Multisig is the precedent: V3.0 emits
  `EnvelopeError::RequiresMultisigSupport` ("this wallet file
  requires Shekyl V3.1 or later") for capability mode `0x04`. The
  same forward-compat pattern (V3.1 either reuses the
  `wrap_count != 1` slot to discriminate hardware-token requirement,
  or introduces a new capability mode under a format-version bump)
  applies to MFA without any V3.0 spec change.

The forward-compatible `Credentials<'_>` parameter shape is the
load-bearing API decision: V3.0 callers construct `Credentials` via
`Credentials::password_only(&[u8])` and read the password back
through `Credentials::password()`. V3.1 adds an
`authenticator: Option<AuthenticatorRequest<'_>>` field and a
sibling `Credentials::password_with_authenticator(pwd, auth)`
constructor; existing `password_only` call sites compile unchanged
across the V3.0 → V3.1 boundary.

**Rejected alternatives.**

- *Reserve MFA fields in the V3.0 wallet file format.* Speculation
  about a feature whose design isn't locked. Per
  `15-deletion-and-debt.mdc` ("FOLLOWUPS.md is not a graveyard"),
  reserving format space for unfrozen designs invites design drift
  in the reserved space.
- *Ship MFA in V3.0.* Triples the V3.0 review surface, blocks the
  V3.0 release on FIDO2 design closure, and does so for a feature
  whose threat-model improvement is real but additive.
- *Take `password: &[u8]` directly and break callers at V3.1.*
  Free V3.0 ergonomics, paid for at V3.1 by every call site. The
  forward-compat struct shape is cheap insurance that mirrors the
  same discipline already used elsewhere in the wallet stack
  (`Option<u32> fee_policy_version`, layered config with future
  fields, this Decision Log itself).

**Reference.** Lifecycle commit (this commit);
[`docs/WALLET_FILE_FORMAT_V1.md`](WALLET_FILE_FORMAT_V1.md) §1
(`wrap_count = 0x01` reserved byte) and §3
(`CAPABILITY_RESERVED_MULTISIG = 0x04` precedent);
`docs/FOLLOWUPS.md` *V3.1 → "MFA / hardware-token integration for
wallet file decryption"* for the recovery-model and design-question
detail.

---

## 2026-04-26 — `MalformedScanResult`: producer-bug signal vs. `ConcurrentMutation`

**Decision.** `RefreshError` gains a new variant
`MalformedScanResult { reason: &'static str }`, distinct from
`ConcurrentMutation`. `Wallet::apply_scan_result` returns the new
variant when the result's **internal shape** disagrees with itself,
and reserves `ConcurrentMutation` for **snapshot-disagreement**
between the result and the current `Wallet<S>` state.

The `Wallet::refresh` retry loop (Phase 2a, commit 4) reads the
distinction:

- `ConcurrentMutation` — race between snapshot and merge. **Retry**
  by pulling a fresh snapshot.
- `MalformedScanResult` — the producer emitted a `ScanResult` whose
  internal shape is invalid (out-of-range height, duplicate
  block-hash entry, residual per-height entry left after the apply
  loop). **Do not retry**: re-running the same producer against the
  same daemon will produce the same contract violation. Surface to
  the caller immediately so the bug is visible rather than masked
  by retry-and-eventual-error.

**Concrete contract violations enforced by the merge.**

1. **`block_hashes` length matches the range length.** Length
   mismatch means the producer skipped a height or double-counted
   one.
2. **Every entry lies inside `processed_height_range`.** Out-of-range
   heights would otherwise be silently dropped by the per-height
   apply loop.
3. **No duplicate heights.** `BTreeMap::insert` would silently
   overwrite a duplicate; explicit duplicate-detection turns the
   silent overwrite into an audit-visible error.
4. **`new_transfers` and `spent_key_images` heights are in range.**
   Same drop-on-mismatch silent failure as above, on the additive
   event vectors instead of the per-height index.
5. **Empty range → empty event vectors.** A non-empty event vector
   against an empty range is a producer-side double-counting signal,
   not a no-op.
6. **No residual per-height entries after the apply loop.** The
   per-height map is drained as the loop walks
   `processed_height_range`; a non-empty residue is the in-loop
   audit witness for "every entry consumed exactly once."

**Rationale.** The Copilot review of PR #16 surfaced four defensive
coding gaps in the original `apply_scan_result_to_state`: silent
drop on out-of-range entries, silent overwrite on duplicate
heights, dropped block-hash records before the per-height apply,
and dropped key-image records below the persistence boundary. The
fix that maps every gap to `ConcurrentMutation` would conflate two
different signals: "the wallet moved under us, retry" and "the
scanner emitted nonsense, escalate." The retry loop's bounded
budget (`opts.max_retries`, default 8) would consume eight retries
on a deterministic scanner bug before surfacing it, and a future
"refresh until success" wrapper would loop forever. Splitting the
variant restores the failure-class signal the retry loop needs.

**Rejected alternatives.**

- *Treat all merge-time failures as one `RefreshError::Internal`.*
  Loses the retry-on-race property, which is load-bearing for the
  snapshot-merge pattern.
- *Treat all merge-time failures as `ConcurrentMutation`.* Conflates
  scanner bugs with races; the retry budget burns on bugs that
  cannot be retried out of.
- *Panic on internal-shape failures.* Producer-side defects should
  surface as typed errors at the boundary so the JSON-RPC server
  can serialize them, the CLI can render them, and the GUI can
  decide whether to surface the underlying scanner-bug message or
  a generic "internal scanner error" to the user. A panic would
  kill the wallet process and force the user back through open.
- *Use `&'static str` reason vs. structured enum.* Each contract
  failure is named at its call site rather than enumerated; this
  trades the pattern-match-on-reason ergonomics for the smaller
  cross-crate API surface (the variant ships as a single tuple
  shape with no version-bump risk for a finer-grained reason
  enum).

**Reference.** Phase 2a refresh-driver branch
([`docs/FOLLOWUPS.md`](FOLLOWUPS.md) "strict-contract enforcement
for `apply_scan_result`"); merge module documentation under
`rust/shekyl-wallet-core/src/wallet/merge.rs` (the "Three-stage
merge" docstring); PR #16 Copilot review thread.

---

## 2026-04-26 — Snapshot-merge-with-retry semantics for `Wallet::refresh`

**Decision.** `Wallet::refresh` (lands in Phase 2a, commit 4) drives
sync via the **snapshot-merge-with-retry** pattern instead of
holding a single long-lived lock across the daemon-poll-and-apply
cycle. The sequence per refresh attempt:

1. **Snapshot.** Take a brief read borrow on `Wallet<S>`, build a
   `LedgerSnapshot` (held in `wallet/refresh.rs`) carrying only
   `synced_height` and `reorg_blocks`. Drop the borrow.
2. **Produce.** Call `produce_scan_result(rpc, scanner, &snapshot,
   range, cancel)`. This is the long-running async section; no
   wallet borrow is held while it runs.
3. **Merge.** Take a `&mut self` borrow, call
   `apply_scan_result(result)`. The merge's invariant gate
   (`Wallet::apply_scan_result invariants`, 2026-04-26) verifies
   that the wallet did not move between snapshot and merge.
4. **Retry-on-race.** If the merge returns `ConcurrentMutation`,
   the wallet moved under the snapshot. Pull a fresh snapshot and
   loop. Bounded by `RefreshOptions::max_retries` (default 8). If
   the merge returns `MalformedScanResult`, surface it
   immediately — see the companion entry above.

The producer is `pub(crate)` and lives in `wallet/refresh.rs`. It
owns the daemon-fetch + scanner-call loop, the inter-block
cancellation polling, the per-block retry-with-exponential-backoff
on transient `RpcError`s (capped at `MAX_BLOCK_FETCH_RETRIES = 5`),
and the **single** reorg-rewind detection pass per call.
A second reorg landing during the same producer call is caught by
the merge's `ConcurrentMutation` gate on the next iteration; the
producer never re-detects within the same call.

**LedgerSnapshot is minimal by design.** Two fields suffice
(`synced_height`, `reorg_blocks`) because the merge — not the
producer — performs authoritative spend detection by feeding the
result's full `spent_key_images` vector through
`LedgerIndexes::detect_spends` against the live wallet's owned-output
set. The producer collects every input's key image unfiltered; the
filter happens at merge time. This collapses snapshot size to a
few KB regardless of wallet size and makes the `clone()` cost
bounded.

**Snapshot strategy: clone, not Arc-wrap.** The two fields fit a
single small `Vec<(u64, [u8; 32])>` (capped at the persistence
layer's `DEFAULT_REORG_BLOCKS_CAPACITY`) plus a `u64`. Cloning is
strictly simpler than wrapping in `Arc<…>` and pays a known small
cost up front. If commit-5 benchmarks show `LedgerSnapshot::clone()`
on a hot path under realistic ledger sizes (>1 ms median at 10 k+
transfers), the strategy may shift to `Arc<…>`-behind-the-fields
in a follow-up plan; the producer-facing surface
(`&LedgerSnapshot`) is stable across that change so the migration
does not touch the producer.

**Rationale.** Two converging properties drive the pattern:

- **`&mut self` cannot be held across `.await`.** The legacy
  `shekyl-scanner::sync::run_sync_loop` holds an
  `Arc<Mutex<LiveLedger>>` continuously across daemon polls, which
  is a separate state space from `Wallet<S>` and contradicts the
  `&self`-queries / `&mut self`-mutations discipline. The
  snapshot-merge pattern keeps the wallet-state mutation surface
  to a single brief `&mut self` window per scanned batch.
- **Daemon poll latency dominates refresh wall-clock.** A wallet
  that locks itself for the full RTT*N of a 1000-block scan is
  unusable from a binary that wants concurrent reads (balance
  query, transfer history) — which is exactly the JSON-RPC server's
  load. Snapshot-merge moves the long latency outside the lock.

**Rejected alternatives.**

- *Single long-lived `&mut self` borrow across daemon polls.* The
  `&mut self` shape is incompatible with `.await` across the borrow,
  and even if rewritten with explicit `RwLock` semantics it locks
  out concurrent readers for the entire scan.
- *No retry on `ConcurrentMutation`.* A retry budget is required
  because a sibling call (a parallel start of a second refresh, a
  send that mutates `synced_height` indirectly) is a normal
  operational state, not an error.
- *Unbounded retry on `ConcurrentMutation`.* An adversary that can
  drive sibling-mutation faster than the producer can complete a
  scan would lock refresh in a livelock. The `max_retries` ceiling
  surfaces the livelock as a typed error within bounded wall-clock.
- *Producer holds the writer-preferred `RwLock<Wallet<S>>`'s read
  guard across `.await`.* A read guard held across `.await` blocks
  any concurrent writer for the duration of the scan, which is
  exactly what snapshot-merge avoids.

**Reference.** Phase 2a refresh-driver branch (commits 2–7);
`rust/shekyl-wallet-core/src/wallet/refresh.rs` module docstring;
the `ScanResult` typed-merge-surface entry (2026-04-25) above; the
`apply_scan_result` invariants entry (2026-04-26) above.

---

<!-- Append new entries above this line. Date format YYYY-MM-DD. -->
