# Raw-primitive → domain-newtype migration (work plan)

**Status:** LANDED — `RTN-1…RTN-7` (as of 2026-09-18)
(wire hash returns and header fields). Living work plan for adopting
domain newtypes before the redb writers freeze. Last verified against
this branch 2026-09-17. The June 2026 PR-0 types crate **landed**;
RTN-1…RTN-6 landed in this family PR; RTN-7 (the wire hash surface, gated
by `check_wire_raw_hash_surface.py`) landed 2026-09-18. The
clock-semantics decision in §7 is recorded as a binding entry in
[`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) (2026-06-14 —
"Time fields: block-height vs wall-clock dichotomy + the
`BlockHeight`/`Timestamp`/`BlockCount` type trio").

## 0. HEAD validity (2026-09-17) — grep surface

A June 2026 finding is **not** automatically still owed. This table is the
status of record; a section below that disagrees with a row is
**records-was** (the 2026-06-14 plan), not current.

| Item | Status at HEAD (2026-09-17) | Carrier |
| --- | --- | --- |
| `shekyl-types` crate (`BlockHeight`, `BlockCount`, `Timestamp`, `TxHash`, `BlockHash`, `GlobalOutputIndex`, `OutputIndexInTx`, `KeyImage`, `CurveTreeRoot`, `PrunableHash`, `Timelock`, `PCanonicalId`, `SettlementEpoch`, …) | LANDED (PR 0, June 2026) | `rust/shekyl-types` |
| `PqcAuthHash`, `ShardId`, `LeafIndex`, `BlockWeight`, `LongTermWeight`, `OneTimePubkey`, `CommitmentBytes`, `AttestationRoot`; crate `#![no_std]` | LANDED — RTN-1 | `rust/shekyl-types` |
| Store codecs (`BlockInfo`, `TxIndex`, `OutTx`, `OutKey`, `TxOutputIndices`, `ConnectFacts`) typed; `CurveRoot` deleted in favor of `CurveTreeRoot`; type-only codec change, no `SCHEMA_VERSION` bump | LANDED — RTN-2 | `shekyl-chain-store` |
| `TxIdentity.pqc_auth_hash: Option<PqcAuthHash>` (`PDM-Q-F26`) | LANDED — #768 | DRS §7.7 item 1; `shekyl-chain-rules` |
| `PowHash` — the RandomX longhash as its own `hash32!` member, distinct from `BlockHash` in both directions (a longhash is never a block id; a block id is never compared against a target). Minted by `shekyl-chain-rules::form` from `Substrate::longhash`. **Sibling-lane write (rule 94 §6), disclosed:** minted by DRS-E6 slice 2, which consumes it (`CHAIN_RULES_SLICE_2.md` §4.2), not by an RTN increment | LANDED — 2026-09-19 (E6 slice 2, commit 1) | `rust/shekyl-types`; consumer `shekyl-chain-rules` |
| `shekyl-curve-tree` uses `shekyl-types` `BlockHeight` / `Gindex` (`pub type Gindex = GlobalOutputIndex`) | LANDED — RTN-4 | `shekyl-curve-tree` |
| `shekyl-difficulty` `lwma1_next(BlockHeight, &[Timestamp], &[CumulativeDifficulty]) -> Difficulty`; leftover `shekyl-consensus::Difficulty` deleted (re-export) | LANDED — RTN-5 | `shekyl-difficulty` |
| `TransferDetails` indices/heights typed; `PaymentRequest.expiry` is wall-clock `Timestamp`; CLI `--expiry` unix seconds or duration | LANDED — RTN-6 | `shekyl-engine-state` / CLI |
| `shekyl-wire`'s hash surface: `Transaction::hash()` / `Block::hash()` / `prefix_hash()` returns, the header's hash fields, `Ct::Fcmp.reference_block`; new `PrefixHash`; **gated** by `check_wire_raw_hash_surface.py` | LANDED — RTN-7 ([record](../completed/RTN_7_WIRE_HASH_TYPES.md)) | `shekyl-wire` / `shekyl-types` |
| Money-path `AtomicUnits` adoption (original PR A) | PARTIAL — not this family's freeze gate | original §4 |
| Secret-material wrapping (original PR B) | OPEN, not the redb freeze | original §5 |
| Crypto-object newtypes (original PR E) | DEFERRED — transform-shaped, live in defining crates | original §8 |

**What this family will not do.** Role-tagged heights (`CreationHeight` /
`EvalHeight`) — one [`BlockHeight`], named fields. RPC DTO newtypes
(hex strings in `shekyl-rpc-types`; wallet-rpc / daemon-rpc serde
structs). `shekyl-wire` hash returns and header fields are RTN-7, not
refused. `impl redb::Key for shekyl_types::BlockHeight` (orphan rule —
thin local key wrappers). Bumping `SCHEMA_VERSION` for type-only codec
field changes that encode identically. Putting `Difficulty` in
`shekyl-types` (it is transform-shaped; it lives in `shekyl-difficulty`).

**Payment-request clock (RTN-6 LANDED 2026-09-17, restating §7.2).** Humans /
off-chain invoices use wall-clock [`Timestamp`]. Daemon-internal deadlines
use [`BlockHeight`]. The CLI that shipped `--expiry <height>` (pre-RTN-6)
was a defect against the 2026-06-14 ruling; RTN-6 restored `Timestamp` and
corrected the flag.

Original PR sequence (PR 0 / A / B / C / D / E) is the 2026-06-14
unbundling. **RTN-1…RTN-6** landed; **RTN-7** is the remaining
wire-return adoption, registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2.

## 1. Thesis & precedent

The `wallet2.cpp` port carried over C++'s habit of representing distinct
domain concepts as interchangeable raw scalars (`u64`, `u128`) and byte
arrays (`[u8; 32]`, `Vec<u8>`). Two of these have already been fixed and are
the templates for everything below:

- **`AtomicUnits(u64)`** ([`shekyl-units/src/lib.rs`](../../rust/shekyl-units/src/lib.rs)) —
  checked-only arithmetic, unit-marked `Display`, `#[repr(transparent)] +
  #[serde(transparent)]`, edge-only `from_raw` / `to_raw`.
- **`KeyImage`** — already adopted in
  [`transfer.rs`](../../rust/shekyl-engine-state/src/transfer.rs) with the
  explicit note: transparent over `[u8; 32]`, *on-disk format unchanged*.

The bug classes a newtype removes by construction:

1. **Silent arithmetic wrap** on money paths (no operator impls; checked-only).
2. **Identity confusion** — a block hash passed where a tx hash is expected,
   a wall-clock timestamp subtracted from a block height, a scalar passed
   where a point is expected.

This is a priority-1 (security) property per `00-mission.mdc` for the money
and secret paths, and a correctness/auditability property elsewhere.

### The version-bump fact this unlocks

A transparent newtype (`#[repr(transparent)] + #[serde(transparent)]`) is
wire- and ABI-identical to the primitive it wraps. The `KeyImage` swap in
`transfer.rs` already proved a `[u8; 32]` → transparent-newtype field change
is byte-identical on disk and needs **no** serialized-format version bump
(`42-serialization-policy.mdc`). The one caveat: `postcard-schema` derives a
*named* schema, so a field type rename `[u8; 32]` → `TxHash` may still change
the committed `.snap` and require `UPDATE_SNAPSHOTS=1` regeneration — a
mechanical regen, **not** a `LEDGER_BLOCK_VERSION` bump. The first task of any
persisted-field PR is to confirm which of the two applies per field.

## 2. The home-crate decision (PR 0, blocks C & D)

State-shaped identity/height types are needed by many crates (consensus,
scanner, tx-builder, engine-state, economics, staking, difficulty). Today they
are scattered and mishoused:

- `BlockHeight(u64)`, `Gindex(u64)`, `TreePosition(u64)` live in
  **`shekyl-curve-tree`** — the wrong home for wallet/consensus-wide
  vocabulary (`18-type-placement.mdc`: state-shaped types live with their
  semantic owner, and curve-tree is not it).
- `TxHash([u8; 32])` lives in **`shekyl-engine-core/src/engine/pending.rs`** —
  too deep; `shekyl-engine-state` cannot reach it cleanly, so `transfer.rs`
  redefines raw `[u8; 32]`.

**Decision needed (PR 0):** introduce a foundational `shekyl-types` crate (or
extend `shekyl-units`) to host the shared state-shaped newtypes:
`BlockHeight`, `BlockCount`, `Timestamp`, `BlockHash`, `TxHash`,
`GlobalOutputIndex`, `OutputIndexInTx`. Everything else re-exports/imports from
there. This PR also resolves the `Gindex` vs `GlobalOutputIndex` naming
collision (pick one canonical name). Per `18-type-placement.mdc`, record the
transform-vs-state disposition of each new type in PR 0's commit body. No
call-site changes in PR 0; validation surface is "the types compile,
round-trip serde-identically, and the schema-snapshot harness sees them."

## 3. PR sequence (unbundled by validation surface)

Each PR is its own validation surface (`19-validation-surface-discipline.mdc`).
They are deliberately **not** bundled: "they're all about types" is the
topic-coherence trap that rule names. Ordering:

`PR 0` → `PR A` ∥ `PR B` → `PR C` → `PR D` → `PR E`.
A and B are independent (parallel); C and D both depend on PR 0.

## 4. PR A — Money path → `AtomicUnits` (Priority 1, security)

Validation surface: **no raw `u64` amount remains on a money path.** Adopt the
existing `AtomicUnits` everywhere a raw `u64` *amount* persists or flows.

| Location | Field | Note |
|---|---|---|
| [`transfer.rs`](../../rust/shekyl-engine-state/src/transfer.rs) | amounts via `Commitment` accessor — audit completeness | persisted |
| [`payment_request.rs:84`](../../rust/shekyl-engine-state/src/payment_request.rs) | `amount_atomic: u64` | persisted |
| [`shekyl-curve-primitives` `Commitment.amount`](../../rust/shekyl-curve-primitives/src/lib.rs) | `amount: u64` | first-party (relocated from shekyl-oxide); edge accessor |
| `shekyl-wire` transaction `fee` | `fee: u64` | the oxide `fcmp.rs` `ProofBase.fee` was deleted in the slice-1 wire extraction; the fee now lives on the genesis tx in `shekyl-wire` (see the `tx-builder wire.rs:26` row below) |
| [`tx-builder wire.rs:26`](../../rust/shekyl-tx-builder/src/wire.rs) | `fee: u64` | |
| economics [`burn.rs:27-29`](../../rust/shekyl-economics/src/burn.rs), [`params.rs`](../../rust/shekyl-economics/src/params.rs) `EconomicParams::emission_curve_asymptote`, emission returns | reward/fee/supply | |
| staking [`registry.rs:9`](../../rust/shekyl-consensus/src/registry.rs) `StakeEntry.amount` | | |

## 5. PR B — Secret-material hardening (Priority 1, security; `35-secure-memory.mdc`)

Validation surface: **no secret key material sits in unwrapped `Vec<u8>` /
`[u8; N]`** — wipe-on-drop is structural, not manual. Overlaps the existing
zeroize-check CI, which is the natural test home.

| Location | Issue |
|---|---|
| [`signature.rs:33-36`](../../rust/shekyl-crypto-pq/src/signature.rs) `HybridSecretKey.{ed25519,ml_dsa}: Vec<u8>` | `#[zeroize(drop)]` at struct level, but raw `Vec<u8>` can leave reallocated copies; rule 35 wants `Zeroizing<Vec<u8>>` newtypes |
| [`kem.rs:86`](../../rust/shekyl-crypto-pq/src/kem.rs) `HybridKemSecretKey.ml_kem: Vec<u8>` | decap key — secret, unwrapped |
| [`output.rs:1023-1026`](../../rust/shekyl-crypto-pq/src/output.rs) `ProofSecrets` `ho/y/z/k_amount` | covered by struct `ZeroizeOnDrop`, but per-field newtypes prevent scalar mix-ups |
| [`reserve_proof.rs:50`](../../rust/shekyl-proofs/src/reserve_proof.rs) `spend_secret: [u8;32]` | should take `&SpendSecret` |
| [`handle.rs:188`](../../rust/shekyl-crypto-pq/src/handle.rs) `view_secret: &[u8;32]` | should take `&ViewSecret` (code comment already flags the gap) |

## 6. PR C — Hash identity (`TxHash` / `BlockHash` / `CurveTreeRoot`) — records-was 2026-06-14; the two wire rows LANDED as RTN-7

Validation surface: **a block hash cannot be passed where a tx hash (or tree
root) is expected.** Finish the `KeyImage`-style migration `transfer.rs`
started. Most are transparent → no version bump (confirm snapshot regen per
field per §1).

| Location | Field |
|---|---|
| [`transfer.rs:88`](../../rust/shekyl-engine-state/src/transfer.rs) `tx_hash`, `:31` `reference_block` | persisted |
| [`ledger_block.rs:107,140`](../../rust/shekyl-engine-state/src/ledger_block.rs) `tip_hash`, `ReorgBlocks` | persisted |
| [`sync_state_block.rs:75,86`](../../rust/shekyl-engine-state/src/sync_state_block.rs) `creation_anchor_hash`, `pending_tx_hashes` | persisted |
| [`tx_meta_block.rs:174,178`](../../rust/shekyl-engine-state/src/tx_meta_block.rs) map keys keyed by txid | persisted |
| [`consensus types.rs:18,25`](../../rust/shekyl-consensus/src/types.rs) `prev_hash`, `top_hash` | |
| `shekyl-wire` block `previous` / `curve_tree_root` / `transactions` | **LANDED — RTN-7** (2026-09-18): `BlockHash` / `CurveTreeRoot` / `Vec<TxHash>`, plus `attestation_root: AttestationRoot` and `BondPost.p_canonical_id: PCanonicalId`. Type-only; every parity KAT unchanged. |
| `shekyl-wire` `Transaction::hash()` / `hash_with_supplied_*` **return**, `Block::hash()`, `prefix_hash()` | **LANDED — RTN-7** (2026-09-18): `TxHash`, `BlockHash`, and the new `PrefixHash` (the txid preimage's *first* component, minted beside `PqcAuthHash` and `PrunableHash` rather than as a signing-specific name — Q3). ~160 call sites in 12 crates; the component surface (`prunable_hash() -> PrunableHash`, `pqc_auth_hash() -> Option<PqcAuthHash>`) was typed with `PDM-Q-F26` the day before. Held by `scripts/ci/check_wire_raw_hash_surface.py`. |
| curve-tree [`types.rs:189-191,245-250`](../../rust/shekyl-curve-tree/src/types.rs) `reference_block`/`tree_root`/`curve_tree_root` | |

## 7. PR D — Heights, indices, timestamps (the clock-semantics decision)

Validation surface: **height ↔ timestamp ↔ index transposition is
unrepresentable.** This is the PR where the CryptoNote `unlock_time` glitch is
designed out, not transcribed. The full reasoning is below; the binding rule
is recorded in the decision log (see §Status).

### 7.1 The governing principle

CryptoNote's mistake was applying one mental model — and one `uint64` — to two
fundamentally different kinds of deadline, and even letting a single field be
*either*: `Timelock::Block(usize) | Time(u64)` and the RPC `unlock_time`
overload are the same glitch — a value whose clock you cannot tell from its
type. The V3 wallet already states the resolution for one class in
[`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) (`PendingTx`): "**No
clock-based TTL** — the real expiration condition is chain state."

The classification test, applied to every time-shaped `u64`:

1. **Who evaluates the deadline?** Consensus (validators must agree) → height.
   A single local wallet, or two parties exchanging a message → candidate for
   wall-clock.
2. **What is it compared against?** On-chain events (maturity, spend
   eligibility, claim windows) → height, because those events *are* heights.
   Human intent / cross-party UX → wall-clock.
3. **What breaks if the clock is wrong?** A fork or a manipulable lock →
   height. Wall-clock here is a footgun: block timestamps are miner-influenced
   within the median-time-past window, so a *time-based consensus lock* is both
   fuzzy and attackable (the Monero `Timelock::Time` cautionary tale). A
   cosmetic "invoice expired 4 minutes early" → wall-clock is fine; blast
   radius is contained to non-consensus UX.

### 7.2 Per-field disposition

| Field | Clock | Type | Why |
|---|---|---|---|
| `oxide::Timelock` | **Height** | `Block(BlockHeight)` — **delete the `Time(u64)` variant** | Consensus-evaluated output lock. Time-mode is the classic manipulable footgun; V3 "we can do better" → height-only. |
| `StakeClaim.from_height/to_height`, `stake_lock_until`, `eligible_height`, `block_height`, `spent_height`, reorg `fork_height`, `built_at_height` | **Height** | `BlockHeight` | Chain-objective; compared against on-chain events. |
| engine-rpc `TransferParams.unlock_time` | **N/A — drop it** | — | V3 `TxRequest` is `{dest, amount, priority}` ([plan §"Send"](WALLET_REWRITE_PLAN.md)) — no unlock field. This RPC `unlock_time: u64` is legacy CryptoNote RPC shape that contradicts the V3 design. Don't newtype it; remove it (or, if a send-time lock is ever wanted, `unlock_height: BlockHeight`). |
| `PaymentRequest.created_at` / `expiry` | **Wall-clock** | `Timestamp` | Off-chain invoice. Travels in a `shekyl:…?expiry=` URI to a *payer* who may be unsynced or a different wallet — wall-clock is evaluable offline and human-set. Not consensus; the merchant's own wallet owns the lifecycle. |
| `SpendIntent.created_at` / `expires_at` | **Wall-clock** | `Timestamp` | Coordination-TTL among cosigners. Chain-binding is *already* handled separately by `reference_block_height` + `reference_block_hash` + `chain_state_fingerprint` + `tx_counter`; `expires_at` is purely a "proposal is stale" hint, evaluable by a cosigner momentarily behind on sync. |
| `AddressProvenance.first_imported_at` / `last_used_at` | **Wall-clock** | `Timestamp` | Pure wallet-local audit metadata. "When did *I* import this" is a wallet action, not a chain event; height is not meaningful if the wallet was offline at import. |

### 7.3 The type trio

Three distinct newtypes, not one, because the entire payoff is that a field's
clock is visible in its signature and illegal arithmetic does not compile:

- **`BlockHeight`** — an absolute chain instant. Used for consensus /
  on-chain-compared deadlines.
- **`Timestamp`** — wall-clock Unix seconds, UTC. Used for off-chain,
  human-facing, cross-party, or wallet-local-audit deadlines.
- **`BlockCount`** — a *relative* block duration, distinct from `BlockHeight`
  (an absolute instant), mirroring `Duration` vs `Instant`. `StakeTier.lock_blocks`
  is a `BlockCount`, not a height.

Arithmetic the types should permit / forbid (catches a real staking-math bug
class for free):

- `BlockHeight + BlockCount = BlockHeight` ✓ (`stake_lock_until = block_height + tier.lock_blocks`)
- `BlockHeight - BlockHeight = BlockCount` ✓
- `BlockHeight + BlockHeight` — does not compile ✗
- `BlockHeight - Timestamp` — does not compile ✗

### 7.4 Other PR-D index sites

`GlobalOutputIndex` / `OutputIndexInTx` adoption: `TransferDetails`
([`transfer.rs:89-91`](../../rust/shekyl-engine-state/src/transfer.rs)),
scanner [`output.rs:26,54`](../../rust/shekyl-scanner/src/output.rs) /
`claim.rs`, tx-builder
[`types.rs:258`](../../rust/shekyl-tx-builder/src/types.rs),
oxide `StakeClaim.staked_output_index`. `internal_output_index` (position
within a tx, can be sparse) and `global_output_index` (dense, ledger-wide) are
different types — that distinction is part of the validation surface.

### 7.5 The consensus-path priority (C++) — where a height transposition is catastrophic

Strong types are used at the *edges* — the C++ DB layer
(`shekyl::db::{BlockHeight, OutputIndex, MaturityHeight, TreePosition}`,
`shekyl_types.h:100-122`) and inside the
Rust curve-tree crate — while the **consensus validation path** (`blockchain.cpp`) and
the FFI seam still run on bare `uint64_t`. The middle, where transposition is most
catastrophic, is exactly where the types stop. Ranked by value (flagged 2026-06-25 from
the un-vendor slice-2 review; this is prioritization *within* PR D, on the C++ validation
surface — landing on its own PR per §3, **not** bundled into a Rust crate move):

1. **The FCMP `referenceBlock` window + curve-tree-depth check**
   (`blockchain.cpp:3946-3964`) — **highest single win.** `chain_height` and `ref_height`
   are both bare `uint64_t`, mixed in the window arithmetic
   (`ref_height > chain_height - MIN_AGE`, …), then `ref_height` is passed straight into
   `get_curve_tree_root_at_height(ref_height)` and written to `*pmax_used_block_height`.
   Four distinct height-derived quantities live here — tip/`chain_height`, `ref_height`,
   `eligible_height`, `MaturityHeight` (+60) — plus `REF_ANCHOR_AGE=6` vs `SPENDABLE_AGE=10`,
   all `u64`. Transposing any of them, or subtracting the wrong AGE constant, silently
   anchors a membership proof to the wrong block — a consensus corruption that compiles
   clean. The strong types already exist (`db::BlockHeight`, the curve-tree
   `ReferenceBlock`); they are simply not used in the validator. **Fix here first.**
2. **`add_staked_outputs(tx, uint64_t creation_height, uint64_t eval_height)`** (`:2050`) —
   two adjacent bare heights, different semantics, live staking path.
   `StrongId<BlockHeightTag>` stops height↔index/amount confusion but **not** height↔height;
   give this pair distinct tags (`CreationHeight`/`EvalHeight`) or a named two-field struct.
3. **The two-bare-`u64` lookups** — `get_output_key(amount, global_index)` (`:2653`),
   `get_output_key_mask_unlocked(amount, index, …)` (`:2705`),
   `get_output_distribution(amount, from_height, to_height, start_height, …)` (`:2715`).
   Caveat: these are the legacy amount-indexed ring path §2.1 Q1 says FCMP++ doesn't use
   (`amount` is 0) — resolve **shed-or-type** explicitly rather than leaving them bare.
4. **Archival consensus scalars are bare** (`bond_wire.rs:70` `shard_ids: Vec<u64>`;
   `settlement_epoch`, `leaf_index_in_segment`, `global_output_index`) — they enter the
   §9.11 sig-preimage; a `ShardId`/`SettlementEpoch` transposition breaks the signature or
   binds the wrong commitment. Add `ShardId`/`SettlementEpoch`/`LeafIndex` (the transparent
   `u64` macro is right there in `shekyl-types`; `KeyImage`/`AtomicUnits` are the precedent),
   reuse `Gindex` for `global_output_index`. Transparent → no wire/format-version bump.
5. **The FFI seam — keep bare primitives ≤3 lines deep.** The C-ABI boundary necessarily
   uses scalars (`shekyl_difficulty_lwma1_next(…, chain_height: u64, …)`); the discipline is
   that the wrapper on each side reconstructs the strong type *immediately* so bare `u64`
   heights never propagate into consensus logic. Today the C++ anon-namespace helpers hand
   bare `uint64_t` straight into validation — bracket them.

## 8. PR E — Crypto object newtypes (lower priority, larger surface)

Points / scalars / signatures / ciphertexts in crypto-pq / proofs / fcmp /
curve-tree. Transform-shaped → live in their defining crate
(`18-type-placement.mdc`). Lower priority because they are mostly internal to
crypto and less prone to the cross-domain confusion that bites the wallet path.

- `HybridSignature` & `HybridPublicKey.ml_dsa` blobs ([`signature.rs:28,49-50`](../../rust/shekyl-crypto-pq/src/signature.rs))
- `DleqProof.{c,s}` ([`dleq.rs:28`](../../rust/shekyl-proofs/src/dleq.rs))
- `ml_kem_ct` / `x25519_eph_pk` ([`tx_proof.rs:230-231`](../../rust/shekyl-proofs/src/tx_proof.rs))
- FROST shares/keys ([`frost_sal.rs`](../../rust/shekyl-fcmp/src/frost_sal.rs), [`frost_dkg.rs:232`](../../rust/shekyl-fcmp/src/frost_dkg.rs))
- Selene leaf x-coords ([`leaf.rs:55-59`](../../rust/shekyl-fcmp/src/leaf.rs))

## 9. Explicitly out of scope

- **`shekyl-oxide` low-level crypto primitives** (field/curve arithmetic,
  hash-to-point, divisors, generators, proof circuit internals) — genuine
  upstream; the raw representation *is* the contract. Only the oxide
  application/protocol layer (transactions, blocks, ringct, rpc DTOs) is "ours
  to type."
- **RPC/JSON DTO edges** ([wallet-rpc](../../rust/shekyl-wallet-rpc/src/lib.rs),
  [daemon-rpc](../../rust/shekyl-daemon-rpc/src/types.rs)): keep raw at the
  wire, convert inward — do not newtype the serde struct itself.
- **`shekyl-encoding`, `shekyl-chacha`, `shekyl-crypto-hash`**: correctly
  generic; no domain types pass through.

## 10. Related rules

- `18-type-placement.mdc` — transform vs state; where each newtype lives.
- `19-validation-surface-discipline.mdc` — why the PRs are unbundled.
- `30-cryptography.mdc` / `35-secure-memory.mdc` — secret material wrapping (PR B).
- `42-serialization-policy.mdc` — when a persisted-field change needs a version bump.
- `60-no-monero-legacy.mdc` — the `unlock_time` / `Timelock::Time` deletions.
