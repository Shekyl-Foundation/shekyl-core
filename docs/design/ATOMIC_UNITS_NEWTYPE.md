# `AtomicUnits` amount-newtype — design note

**Status:** **implemented** (interim PR, 2026-06-05). This note was written
scope-first per `05-system-thinking.mdc` ("specification first, code second")
to fix the scope, type contract, complete conversion-edge boundary, and
migration discipline before code; it now documents the landed design. The
`shekyl-units` crate owns `AtomicUnits`; the amount domain carries it; raw
`u64` survives only at the §4 edges; the CLI display is reconciled to `10^9`.
`fmt` / `clippy -D warnings` / per-crate `test` are green.

**Timeframe (`05-system-thinking.mdc`):** addresses **now** (pre-genesis
wallet correctness). The type is forward-compatible with the mining-era and
V4 timeframes because it is a pure `u64` newtype with no consensus constant
baked in; the one place a future consensus surface attaches (the deferred
`mul_div_rem` reward primitive) is named below with an explicit reopening
criterion.

---

## 1. Why this type exists

Shekyl amounts are raw `u64` today, inherited from Monero. Raw `u64` on a
money path is two latent bug classes at once:

1. **Silent wrap.** `a + b` wraps in release builds. On a confidential-amount
   chain an overflow turns a huge balance into a tiny one with nothing
   visible on-chain — an inflation/accounting fault no observer can audit.
2. **Unit confusion.** Display units (SKL) and atomic units differ by a
   factor of `10^9`. Conflating them is the exact bug that broke the
   *original* Shekyl chain (see §6).

`AtomicUnits(u64)` makes both unrepresentable by construction: arithmetic is
**checked-only** (silent wrap doesn't compile), and the type is **always**
atomic integer units with display formatting available only through an
explicit, single-sourced conversion.

Priority hierarchy (`00-mission.mdc`): this is a **priority-1 (security)**
change — it removes a silent-corruption surface on the money path. It is
privacy- and feature-neutral.

---

## 2. Type-placement disposition (`18-type-placement.mdc`)

`AtomicUnits` is **state-shaped**: it is a value that flows through balances,
fees, recipients, and persisted ledger state, not the output of one defining
cryptographic transform. It therefore lives in a foundational crate that the
state/computation layers can all depend on, **not** in a crypto crate.

No existing crate is a common dependency of every amount-bearing crate, so
the type gets a new foundational crate: **`rust/shekyl-units`** (deps:
`zeroize`, `serde`; build-dep `serde_json`). Crypto crates
(`shekyl-crypto-pq`, the `shekyl-oxide` fork) keep consuming `u64`/bytes —
they do not depend on `shekyl-units`.

---

## 3. Type contract

```text
AtomicUnits(u64)          // private inner field
  derive: Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Zeroize,
          Serialize, Deserialize   (+ #[serde(transparent)], #[repr(transparent)])
  NO  Debug derive  (hand-written, see below)
  NO  Hash          (no amount-as-map-key consumer; consumer-driven discipline)
  NO  Add/Sub/Mul/Div operator traits
```

### 3.1 Keystone — checked-only, no operator traits

No `Add`/`Sub`/`Mul`/`Div` impls. `a + b` on two `AtomicUnits` **must not
compile**. The surface is:

- `checked_add(self, Self) -> Option<Self>`
- `checked_sub(self, Self) -> Option<Self>`
- `checked_sum(impl IntoIterator<Item = Self>) -> Option<Self>` — the one
  aggregate that grows (claimable-reward sums, balance totals, recipient
  totals)
- `const ZERO`
- `Ord`/`Eq` (derived) for "enough balance?" and sorting

No bare `checked_mul`/`checked_div` (no consumer; see §5 for the deferred
`mul_div_rem`). No `saturating_*` — saturating money is the same
silent-corruption class as wrapping (a saturated sum silently caps at
`u64::MAX`), so the inherited `saturating_add` sites migrate to
`checked_add(...)?`.

The verbosity is the feature: every overflow path is forced to the surface
and handled, which is the mechanical form of "the wallet must not rely on
consensus to mask a local accounting bug."

### 3.2 Boundaries — `from_raw`/`to_raw` only

Private inner field; **no** blanket `From<u64>`/`Into<u64>` (a blanket
conversion would let any `u64` silently become an amount, defeating the
type). Named `const fn from_raw(u64) -> Self` / `const fn to_raw(self) -> u64`
used **only** at the edges enumerated in §4. Those named call sites are the
greppable set that bounds the migration.

### 3.3 Wire/ABI — transparent

`#[serde(transparent)]` ⇒ serializes byte-identically to the inner `u64`
(JSON number, postcard varint, TOML integer). `#[repr(transparent)]` ⇒
ABI-identical at the FFI edge. **Consequence:** the
`amount: u64 → AtomicUnits` swap is a *type-level* change with **no
serialized-format change** and therefore **no `WALLET_LEDGER_FORMAT_VERSION`
bump** (`42-serialization-policy.mdc`: a type change that produces identical
wire bytes is not a wire-format change). Verified for the JSON-RPC surface in
§4.5.

### 3.4 Units & display — single-sourced 10^9, no float

`AtomicUnits` is *always* atomic integer units. No `f64` anywhere in the
amount path.

- `Debug` + `Display`: **hand-written**, render the raw integer **with a unit
  marker** (e.g. `12345 au`), never SKL — a log line or debug print cannot be
  misread as SKL.
- `to_skl_string(self) -> String`: exact integer formatting at fixed
  `DISPLAY_DECIMAL_POINT` decimals (deterministic, matches the existing CLI
  fixed-width output).
- `from_skl_str(&str) -> Result<Self, ParseAmountError>`: the user-facing
  money parser (see §7.3 for the adversarial-input contract).

The `10^9` relationship is **single-sourced from `config/economics_params.json`**
via the crate's own `build.rs` (§6). No hardcoded `1_000_000_000` appears in
the crate.

### 3.5 Copy & secret-amount hygiene

`AtomicUnits` is `Copy` (parity with today's `u64`; move-only would be
ergonomically brutal for a type used everywhere) and `Zeroize` (so the
secret container that holds it keeps compiling, §8). **Recorded tradeoff:** a
`Copy` amount can leave un-zeroized copies on the stack. This is exactly the
posture today with raw `u64`; the newtype does not worsen it. Secret hygiene
stays at the *container* level (`OutputClaim` is `ZeroizeOnDrop`). Move-only
secret-amount hygiene would be a separate, heavier decision.

---

## 4. Complete conversion-edge inventory

This is the **full** raw-`u64` boundary — the complete `to_raw`/`from_raw`
set, not "three edges plus an unstated oxide." Everything inside the boundary
carries `AtomicUnits`; conversion happens only at these sites.

### 4.1 oxide fork `u64` surface (vendored; stays `u64` per `10-shekyl-first`)

The fork is a downstream consumer and never depends on `shekyl-units`. SHEKYL
→ oxide *write* sites each get a named `to_raw`:

- **`Commitment.amount`** via `Commitment::new(mask, amt.to_raw())`
  (`rust/shekyl-oxide/shekyl-oxide/primitives/src/lib.rs:114`).
- **tx `fee: u64`** (`rust/shekyl-oxide/shekyl-oxide/src/fcmp.rs:110`,
  varint) — a **separate field** from the commitment, set from the now-
  `AtomicUnits` `fee_estimator` output. Named explicitly so it is not folded
  under "convert at `Commitment::new`."
- output amounts `Option<u64>`
  (`rust/shekyl-oxide/shekyl-oxide/src/transaction.rs:49`, `:144`) and the
  claim-reward `amount: u64` (`:58`) where SHEKYL builds the tx/claim.

### 4.2 Multisig signed-hash edges (`shekyl-engine-core/src/multisig/v31/intent.rs`)

Amounts are serialized into a **signed** digest, so they are byte-stable
`to_raw` edges, not merely arithmetic:

- `IntentRecipient.amount` + `SpendIntent.fee` → `to_canonical_bytes`
  (`:206`, `:209`) → `intent_hash` (signed).
- `ChainStateFingerprint.input_amounts` → `compute` (`:404`, `cn_fast_hash`).

Migrate the fields to `AtomicUnits`; write `amt.to_raw().to_le_bytes()` at
the hash sites so the signed digest stays byte-identical. `validate_balance`
already uses `checked_add`/`try_fold`; migrate its `&[u64]` → `&[AtomicUnits]`
+ `checked_sum`.

### 4.3 FFI (`rust/shekyl-ffi/src/lib.rs`)

`ShekylScannedOutput.amount`, `ShekylBurnSplit`, `shekyl_stake_weight`,
`*amount_out` stay `#[repr(C)] u64`. Convert at the wrapper only where a
now-`AtomicUnits` Shekyl function is called. Mostly automatic, since the
crates the FFI delegates to (`crypto-pq`, `economics`) stay `u64`.
`src/shekyl/shekyl_ffi.h` stays in sync (`25-rust-architecture.mdc`).

### 4.4 postcard `commitment_bytes` (`shekyl-engine-state/src/serde_helpers.rs`)

The only persisted amount carrier is `TransferDetails.commitment`, which is
fork-`u64`. Conversion at the `commitment_bytes` serializer (`:105`, `:123`).
`#[serde(transparent)]` means no persisted-state migration — and pre-genesis
there is none anyway.

### 4.5 JSON-RPC `TransferDestination.amount` (`shekyl-engine-rpc/src/types.rs:171`)

**Verified at source:** derives plain `Serialize`/`Deserialize` over `u64` ⇒
serializes as a JSON **number**. `#[serde(transparent)]` over `AtomicUnits`
preserves the number ⇒ no format change, no version bump.

> **Pre-existing latent bug (not introduced, not fixed here):** amounts up to
> ~`4.29e18` exceed JavaScript's `2^53` safe-integer ceiling when serialized
> as bare JSON numbers. The standard mitigation is string-amount serde
> (Monero/Bitcoin), which is itself a format change — tracked as a FOLLOWUPS
> item, not this PR. `AtomicUnits` is the natural home for the string
> serializer when it lands.

---

## 5. Deferred: the reward `mul_div_rem` primitive

The entitlement reward is `floor((N · amount) / D)` with a committed,
range-proven remainder `ρ`. `N · amount` exceeds `u64` for valid rewards
(`amount` runs near total supply ~`2^62`), so the computation needs a `u128`
intermediate, and because wallet and consensus must agree to the atomic unit,
the primitive is a **consensus-agreement surface**, not just a safety helper.

**This primitive already exists** and is **not** in this PR's scope:
`shekyl-staking/src/entitlement.rs::reward_and_remainder(n, amount, k) ->
(u128, u128)` is u128-native, returns `(reward, ρ)`, and is property-tested
with `assert!(denominator(k).is_power_of_two())` (the power-of-two `D` that
makes `floor(·/D)` an exact shift and `ρ` an exact mask, so there is no
rounding mode for wallet and consensus to disagree on). The in-scope
`rewards.rs::distribute_staker_rewards` is a *different* computation
(proportional pool split, already in `u128`, no committed remainder).

Adding a duplicate `mul_div_rem` to `AtomicUnits` now would be (a)
pre-provisioning (its only natural consumer is the u128-native consensus
module that already owns the math) and (b) a `18-type-placement.mdc`
consensus-surface duplication.

**Reopening criterion (`21-reversion-clause-discipline.mdc`):** introduce an
owned `AtomicUnits::mul_div_rem` when the entitlement / confidential-staking
reward path is migrated to `AtomicUnits`. Re-evaluation shape: a design round
of that migration PR. Tracked in `docs/FOLLOWUPS.md`.

---

## 6. The `10^9` denomination — canonical, u64-mandated, single-sourced

`10^9` is **not a readability preference**; it is a hard `uint64_t`
representability constraint. With a headline supply of `2^32` whole SHEKYL,
the atomic-unit ceiling is `2^32 × 10^decimals`, which must stay under
`2^64 − 1`:

| decimals | max supply (atomic) | vs `u64::MAX` (~1.84e19) |
|----------|---------------------|--------------------------|
| **9**    | `4.29e18`           | ~4.3× headroom           |
| 12       | `4.29e21`           | overflows by ~233×       |

So 9 is the **largest** precision that fits a `2^32` supply in `u64`.
Readability drove the *supply size* (`2^32` ⇒ billions of whole coins, so
everyday amounts aren't dust); given that supply and the `u64` constraint, 9
decimals falls out as the maximum.

This is the same `4.3×` headroom that lets `AtomicUnits` be a `u64` newtype
at all (rather than `u128`, which would be awkward at the ABI-identical
`to_raw` FFI edge) — and the one place even `4.3×` is insufficient is the
deferred `mul_div_rem`, which is exactly why it widens to `u128`. The
denomination choice and the type design are the same decision seen from both
ends.

**Why it keeps resurfacing:** the original Shekyl chain launched with
Monero's `COIN = 10^12` and `MONEY_SUPPLY = 2^32` left unadjusted; since
CryptoNote interprets `MONEY_SUPPLY` in atomic units, the effective whole-coin
ceiling was `2^32 / 10^12 ≈ 0.0043` SHEKYL — the chain crossed its supply
ceiling within a handful of blocks and paid only the tail-emission floor for
its entire ~8-year life. `10^9` is the correction of exactly that constant.

**Single source of truth.** The reboot moved the value out of scattered
`cryptonote_config.h` hardcoding into `config/economics_params.json`
(`"coin": 1000000000`, `"display_decimal_point": 9`) → generated headers.
`shekyl-units` gets its **own `build.rs`** (mirroring the
`shekyl-economics` / `shekyl-difficulty` / `shekyl-staking` build scripts)
reading those two fields and emitting `ATOMIC_UNITS_PER_SKL: u64` and
`DISPLAY_DECIMAL_POINT: u8`. A const assertion guards drift:

```rust
const _: () = assert!(ATOMIC_UNITS_PER_SKL == 10u64.pow(DISPLAY_DECIMAL_POINT as u32));
```

`shekyl-units` thus becomes the canonical Rust *owner* of the `10^9`
relationship — sourced from the JSON, with no hardcoded literal and no
`shekyl-economics` dependency (the foundational crate can't depend on a
higher-level domain crate; the eventual `economics → units` consolidation is
a FOLLOWUPS item, §10).

---

## 7. Migration discipline (write into code review, not improvised per-site)

### 7.1 Fallibility ripple (`20-rust-vs-cpp-policy.mdc`)

Checked-only turns previously-infallible `+`/`saturating_add` sites fallible.
Arithmetic sites (`fee_estimator`, `tx-builder/validate`, `output_selector`,
`staking/rewards`, `multisig/intent`) gain or route an "amount overflow"
error variant and the enclosing fn returns `Result`. Pure-comparison/format
contexts (`Ord`, `Display`, getters, `const fn`) do **no** arithmetic and are
unaffected — they don't ripple.

### 7.2 `None` is an error, never a default

The safety win evaporates if a `checked_*` result is defaulted with
`unwrap_or(ZERO)` — that swaps silent *wrap* for silent *zero*. On
invariant-protected sites, `None` is a real bug and must surface as an
error/assertion. Canonical case: staking dust =
`pool.checked_sub(distributed)` where `pool ≥ distributed` is the invariant —
`None` means real over-distribution and must error, **not** `unwrap_or(ZERO)`.
The migration rule is: **route through checked *and* propagate `None` as an
error on invariant sites.**

### 7.3 `from_skl_str` adversarial-input contract

`from_skl_str` replaces the inherited CLI `parse_amount`, making it the
user-facing money-input path — a prime bug surface. It must:

- **reject** (not silently truncate) more than `DISPLAY_DECIMAL_POINT`
  fractional digits — truncating money is corruption;
- **error** when the parsed value `× 10^9` exceeds `u64`;
- **reject** negative, empty, multiple-dot, trailing-junk, and lone-`.`
  inputs.

`to_skl_string` is pinned to **fixed `DISPLAY_DECIMAL_POINT` decimals** so the
round-trip is total and CLI output is deterministic.

---

## 8. The secret-site intersection (`35-secure-memory.mdc` × `36-secret-locality.mdc`)

The single most important constraint. `OutputClaim.amount_atomic_units`
(`rust/shekyl-engine-core/src/engine/traits/key.rs:250`) is the one
amount field that is a **secret**: `OutputClaim` is `#[derive(Clone,
ZeroizeOnDrop)]` with a hand-written `Debug` that renders the field as the
literal `"[REDACTED]"`.

Two requirements follow, both already satisfied by the type contract in §3:

1. `AtomicUnits` **must** `impl Zeroize` (derived) so `ZeroizeOnDrop` on
   `OutputClaim` keeps compiling.
2. `OutputClaim`'s manual redacting `Debug` **must** be preserved verbatim.
   It does not delegate to the field's `Debug`, so the redaction is
   independent of `AtomicUnits`'s own unit-marker `Debug` — migrating the
   field type does not change what `{:?}` on an `OutputClaim` prints. The
   redaction tests must stay green.

---

## 9. Blast radius (migration scope)

~55–60 production sites across the state/computation/orchestration layers.
One crate per commit (`90-commits.mdc`); each commit changes
field/param/accumulator types to `AtomicUnits`, routes arithmetic through the
checked methods, and inserts `to_raw`/`from_raw` only at §4 edges.

| Crate | Representative sites |
|-------|----------------------|
| `shekyl-engine-state` | `TransferDetails::amount() -> AtomicUnits`; `commitment_bytes` edge; `spendable_outputs(min_amount: Option<AtomicUnits>)` |
| `shekyl-engine-prefs` | `min_output_value`, `ignore_outputs_above/below`, `auto_mine_for_rpc_payment_threshold`, `credits_target` (TOML identical via transparent) |
| `shekyl-scanner` | `RecoveredWalletOutput.amount`, `BalanceSummary` (fields + `compute`), `coin_select`, `claim`, `ledger_ext`; amount XOR-encryption stays `u64` (crypto edge) |
| `shekyl-staking` | `rewards.rs`: `StakerReward.amount`, `staker_pool_amount`, distributed/dust (u128 split kept, `to_raw`/`from_raw` at boundary); tier weights + `entitlement.rs` untouched |
| `shekyl-engine-core` | `pending.rs`, `local_pending_tx.rs`, `fee_estimator.rs`, `output_selector.rs`, `claim_builder.rs`, `multisig/v31/intent.rs` (§4.2), `local_keys.rs`/`key_actor.rs`/`fault_injecting_pending_tx.rs`, secret `OutputClaim` site (§8) |
| `shekyl-tx-builder` | `SpendInput.amount`, `OutputInfo.amount`, `validate.rs`/`sign.rs` totals + `fee`, `error.rs::InsufficientFunds`; convert at §4.1 oxide edges |
| `shekyl-engine-rpc` | `TransferDestination.amount` (§4.5) |
| `shekyl-cli` | `format_amount`/`parse_amount` repointed `10^12 → 10^9` via `AtomicUnits` (§6); callers consume `AtomicUnits` |

### Explicitly out of scope (stays `u64`)

The `shekyl-oxide` fork, `shekyl-crypto-pq`, `shekyl-economics` (incl.
burn-split), `entitlement.rs` consensus reward math, and every **non-amount**
`u64` (block heights, output indices, epoch/tier IDs, tier weights,
`total_weighted_stake_lo/hi`, fixed-point scalers, PoW scratchpad sizes).

### Decimal-point deferral liveness (verified)

No Rust formatter reads `default_decimal_point` (`engine-prefs/src/schema.rs`)
or `DEFAULT_DISPLAY_DECIMAL_POINT = 12`
(`shekyl-crypto-pq/src/wallet_state/settings.rs:74`) — every reference is a
store/default/test-assert. The **sole live Rust display path is the CLI
`format_amount`** this PR fixes, so deferring the `12 → 9` correction does
not ship split display on the Rust surface. A C++/FFI consumer of the stored
point belongs to the V3.2 `wallet_rpc_server` cutover, outside the Rust
amount path. Tracked as a consolidation FOLLOWUPS item (§10).

---

## 10. FOLLOWUPS opened by this PR

1. **`AtomicUnits::mul_div_rem`** (rule-21 reopening, §5) — land when the
   entitlement/confidential-staking reward path migrates to `AtomicUnits`.
2. **Constant consolidation** — retire the remaining hand-copied
   `10^9`/decimal constants onto the generated single source via
   `shekyl_units` (`economics → units` dependency direction is legal):
   `entitlement/tests` `COIN: u128`, `DEFAULT_DISPLAY_DECIMAL_POINT = 12`,
   prefs `default_decimal_point` (inherited 12 → JSON's 9). Note that
   `economics-sim`'s `COIN: f64` is a **float in a money path** (the "no
   float" rule) — source the value from the generated constant *and*
   separately assess whether the sim's `f64` modeling math is acceptable.
3. **JSON-RPC large-amount precision** (§4.5) — string-amount serde at the
   RPC edge; a format change, its own PR.

---

## 11. Definition of done

1. This design note (blast radius + complete edge inventory + verified
   findings).
2. `AtomicUnits` with `Zeroize` + unit-marker `Debug` + preserved
   `OutputClaim` redaction + checked-only (no-operator) arithmetic +
   serde/repr-transparent wire + single-sourced `to_skl_string`.
3. Amount-domain sites migrated; raw `u64` only at §4 edges; CLI display
   reconciled to `10^9`.
4. `fmt`/`clippy`/`test` green; docs (`PHASE_2B` §6/§10.1, FOLLOWUPS close +
   three new items, CHANGELOG) updated.
