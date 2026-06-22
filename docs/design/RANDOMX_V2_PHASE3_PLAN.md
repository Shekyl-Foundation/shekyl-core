# RandomX v2 — Track B Phase 3 plan (genesis PoW cutover: 3a/3b)

## Front-matter

| Field | Value |
|-------|-------|
| Status | Active plan document (Round 0 substrate capture + 3a/3b design). Implementation pending. |
| Parent plan | [`docs/design/RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) — Track B Phase 3 (`phase3-*` todos). |
| Spec authority | [`docs/design/RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) §5 (FFI surface), §6 (no-prewarm), §13 (non-goals), §16 (genesis seedhash), §17 (error taxonomy). This doc **cites**; it does not re-derive. |
| Sibling plans | [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5.11.6 (typed-array-pointer FFI), §5.11.7 (sticky-eviction DoS), §14 Round 5 (C-header form); [`RANDOMX_V2_PHASE2G_PLAN.md`](./RANDOMX_V2_PHASE2G_PLAN.md) (differential harness — light-vs-light only). |
| Base commit | `e63701676` (`dev` tip at survey time; all line numbers in §2 are against this commit). |
| Fork pin | `external/randomx-v2` at `aaafe71` (v2.0.1) — the library miners run; the byte-for-byte parity target for the Hole-1 gate (§7). `external/randomx` (v1, `102f8acf`) is the **outgoing** consensus path. |
| Working branch | `feat/randomx-v2-genesis-cutover` (off `dev`). |
| Scope | Consensus PoW cutover only: v1-C → v2-Rust for verification, CryptoNight removed from the consensus path, genesis flipped to RandomX v2. See §1. |
| Out of scope (deferred, with reversion clauses) | (a) RPC-payment subsystem deletion — §1.2 #1, [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) item. (b) `rx-slow-hash.c` / `slow-hash.c` physical deletion — Phase 3c (blocked by `wallet2.cpp` + RPC-payment). (c) `IPowSchema` / `pow_registry` abstraction deletion + `RX_BLOCK_VERSION` `#define` deletion — Phase 4. (d) `shekyl_pow_randomx_v2_seedheight` FFI export — §5 disposition, reopens at 3c. (e) Worst-case per-hash latency gate — post-2g round per parent §6. |

## 0. Why this document exists

Per [`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc)
"specification first, code second" and
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc),
this document is the design-doc-first step before any Phase 3 code. It
exists because the cutover touches a consensus-rule boundary (the PoW
hash a validating node computes for every block) and the
[`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
C/Rust boundary, both of which the sub-PR discipline requires be
specified, surveyed, and reviewer-mapped before implementation.

It supersedes the ad-hoc cutover sketch that preceded it on three
counts the survey (§2) corrected: (1) the outgoing consensus path is
RandomX **v1**, not v2, so the cutover invariant is the v2 library's
own **light==full** property (§7), not equality with the current
daemon hash; (2) genesis block **identity** is unchanged by the
cutover (§3.2), which collapses the feared "frozen E2E test rework"
to PoW-specific tests only; (3) the `set_canonical` DoS-mitigation
signal (§4) requires a second committed FFI export that the spec's
§5 lists as out-of-surface — a latent corpus gap this doc closes via
a scoped §5/§6/§13 amendment.

## 1. Scope and non-scope

### 1.1 In scope

The cutover moves the **consensus PoW verification path** from the C
RandomX v1 implementation (`crypto::rx_slow_hash` →
`external/randomx`) to the Rust RandomX v2 verifier
(`shekyl-pow-randomx` via a new `shekyl-ffi` export), and removes
CryptoNight from the consensus path:

1. **3a** — Add the `shekyl_pow_randomx_v2_hash` + `…_set_canonical`
   FFI exports; rewire the three consensus `rx_slow_hash` sites and
   the four `rx_set_main_seedhash` sites to them, behind a
   compile-time flag so the legacy v1 path remains buildable for the
   3a review window. Add the Hole-1 parity gate (§7).
2. **3b** — Collapse `get_pow_for_height` to RandomX-only, delete
   `pow_cryptonight.cpp`, delete the two `202612` fossils, remove the
   consensus `RX_BLOCK_VERSION` guards, drop the 3a flag, and verify
   genesis (§8).

### 1.2 Out of scope / deferred

Each deferral carries an explicit reopening criterion per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).

1. **RPC-payment subsystem deletion.** `wallet_rpc_payments.cpp`,
   `rpc_payment.{cpp,h}` and their RPC registrations are dead
   Monero-legacy awaiting deletion (spec §15 "RPC Payments
   Disposition — Delete"). They are the **only** remaining
   non-consensus callers of `crypto::rx_slow_hash`
   (`wallet_rpc_payments.cpp:158`, `rpc_payment.cpp:240`) and of the
   `RX_BLOCK_VERSION` `#define` (`wallet_rpc_payments.cpp:156`,
   `rpc_payment.cpp:237`). **No forcing function** drags them into
   the cutover: 3b leaves the `#define` and the C `rx_slow_hash`
   alive (both already staying until 3c), so this dead code compiles
   untouched. Disposition: leave untouched; record a FOLLOWUPS
   deletion item (target V3.0 pre-genesis). *Reopen criterion:* the
   dedicated RPC-payment deletion PR (or Phase 4) lands; deleting it
   unblocks the `RX_BLOCK_VERSION` `#define` deletion and narrows the
   3c `rx-slow-hash.c` deletion.
2. **`rx-slow-hash.c` / `slow-hash.c` physical deletion (Phase 3c).**
   Blocked: `rx-slow-hash.c` is still referenced by RPC-payment (item
   1) and provides the `rx_seedheight`/`rx_seedheights` the consensus
   callers keep using (§5); `slow-hash.c`'s `cn_slow_hash` is still
   used by `wallet2.cpp` (cache-key derivation / legacy file
   encryption — a Phase 5 wallet target). *Reopen criterion:*
   RPC-payment deleted **and** `wallet2.cpp` migrated.
3. **`IPowSchema` / `pow_registry` abstraction + `RX_BLOCK_VERSION`
   `#define` deletion (Phase 4).** 3b collapses the *dispatch* to
   RandomX-only and deletes the CryptoNight *implementation*
   (`pow_cryptonight.cpp`), but keeps the registry abstraction and
   the `#define`. Full abstraction deletion is the parent plan's
   Phase 4 (its own design/review). *Reopen criterion:* Phase 4
   opens.
4. **`shekyl_pow_randomx_v2_seedheight` FFI export.** Discretionary
   per spec §5 ("only if the caller survey proves the call cannot be
   eliminated or moved to a Rust caller cleanly"). The survey (§5)
   finds the C `rx_seedheight` serves every site and stays until 3c.
   *Reopen criterion:* 3c deletes `rx-slow-hash.c`; the seedheight
   export then lands per spec §16's formula + spec-vector test.
5. **Worst-case (≤5.0×) per-hash latency gate.** Post-2g adversarial
   corpus round per parent §6 line 241. 3a still activates the
   per-PR **average** (≤3.0×) gate per parent §6 line 246.

### 1.3 Why `07-consensus-atomic-cutovers` does not bind

This is a **pre-genesis** change: there is no live chain, no
deployed validators, and no canonical block whose interpretation
could diverge across nodes mid-cutover.
[`07-consensus-atomic-cutovers.mdc`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)
exists to protect against intermediate split points leaving a *live*
chain non-canonical; with no live chain its criterion 2
("indivisible under flag decomposition") is moot — and in fact 3a/3b
**is** a clean flag decomposition (3a default-buildable-legacy → flag
flip → 3b deletes the old path), which is precisely the shape `07`
says *does not* need the exception. The cutover therefore splits
normally under [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc):
3a and 3b are separate PRs.

## 2. Substrate audit (read at `e63701676`)

Per the [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
A2 discipline ("read each site"), every site below was read, not
greped-and-assumed. Line numbers are against `e63701676`.

### 2.1 Consensus `crypto::rx_slow_hash` sites (rewired in 3a)

| File:line | Function | Disposition |
|-----------|----------|-------------|
| `src/crypto/pow_randomx.cpp:16` | `RandomXPowSchema::hash` | swap → FFI hash |
| `src/cryptonote_basic/cryptonote_format_utils.cpp:1488` | `get_block_longhash` (blobdata overload) | swap → FFI hash |
| `src/cryptonote_core/cryptonote_tx_utils.cpp:869` | `get_altblock_longhash` | swap → FFI hash |

Dead (RPC-payment, **left untouched** per §1.2 #1):
`wallet_rpc_payments.cpp:158`, `rpc_payment.cpp:240`.

### 2.2 `crypto::rx_set_main_seedhash` sites (→ `set_canonical`, 3a)

Four call sites, all in `src/cryptonote_core/blockchain.cpp`:
**591** (guard 587), **712** (guard 709), **1418** (guard 1417),
**5590** (guard 5589). Each is `if (… >= RX_BLOCK_VERSION)
rx_set_main_seedhash(seed.data, threads);`. The call is replaced by
`shekyl_pow_randomx_v2_set_canonical(&seed)` (§4); the guard is
dropped in 3b. The `max_dataset_init_threads` argument is **dropped**
— there is no background dataset build (§4.4). Declaration:
`src/crypto/hash-ops.h:101`.

### 2.3 `rx_seedheight` / `rx_seedheights` sites (stay C++; guard-only in 3b)

These compute seed **heights** for block validation; they do not hash
and do not manage the cache. They keep calling the C functions (which
stay until 3c). In 3b only their `RX_BLOCK_VERSION` guards are
removed.

- `rx_seedheight`: `cryptonote_tx_utils.cpp:888`;
  `blockchain.cpp:589, 711, 1399, 2323, 5577`.
- `rx_seedheights`: `blockchain.cpp:1768, 1776, 1830, 1988`;
  `core_rpc_server.cpp:1856`. The wrapping guards are at
  `blockchain.cpp:1765, 1827, 1985` (1765 wraps 1768+1776; 1827 wraps
  1830; 1985 wraps 1988) and the alt-chain guard at
  `blockchain.cpp:2320` (wraps 2323).
- Declarations: `hash-ops.h:98, 99`.

### 2.4 `RX_BLOCK_VERSION` classification

`#define RX_BLOCK_VERSION 12` at `src/crypto/hash-ops.h:95`. Three
buckets:

| Bucket | Sites | 3b action |
|--------|-------|-----------|
| Consensus dispatch | `pow_registry.cpp:15` | collapse to RandomX-only |
| Consensus seed/longhash | `tx_utils.cpp:874` (fossil guard, **delete branch**), `tx_utils.cpp:884` (seed resolution → unconditional), `format_utils.cpp:1486` (RandomX branch → unconditional, delete CN+fossil), `blockchain.cpp:587/709/1417/5589` (call-replacement guards → drop), `blockchain.cpp:1765/1827/1985/2320` (seedheights guards → drop), `core_rpc_server.cpp:1965/2309/3534` (block-template/mining seed_hash → unconditional) | remove guard |
| Dead CryptoNight-variant RPC | `core_rpc_server.cpp:2031` | **delete branch** (rule 60) |
| Dead RPC-payment | `wallet_rpc_payments.cpp:156`, `rpc_payment.cpp:237` | **leave** (§1.2 #1) |

The `#define` itself **stays** in 3b (RPC-payment still references
it); its deletion bundles with §1.2 #1 / Phase 4.

### 2.5 The two `202612` fossils (delete, rule 60)

- `cryptonote_tx_utils.cpp:874-879` — the broken
  `pbc != NULL && major_version >= RX_BLOCK_VERSION` guard returning
  a hard-coded `longhash_202612` (a Monero block-202612 workaround
  with no Shekyl meaning; the missing height check is the latent bug
  that currently routes Shekyl genesis to the CryptoNight
  fall-through).
- `cryptonote_format_utils.cpp:1481-1485` — the `height == 202612`
  branch returning the same constant.

### 2.6 Registry / schema / CryptoNight deletion surface (3b)

- `src/crypto/pow_registry.cpp` — `get_pow_for_height` collapses to
  always return `get_randomx_pow_schema()`; delete
  `get_cryptonight_variant_for_block`.
- `src/crypto/pow_registry.h` — drop `get_cryptonight_pow_schema` and
  `get_cryptonight_variant_for_block` declarations.
- `src/crypto/pow_cryptonight.cpp` — **delete file** + its
  `src/crypto/CMakeLists.txt` entry (rule 60: CryptoNight is deleted,
  not gated). Independent of `slow-hash.c` (it only *calls*
  `cn_slow_hash`; deleting the caller doesn't require deleting the
  callee).
- `src/crypto/pow_randomx.cpp` — **kept** (the RandomX schema); its
  `rx_slow_hash` call is swapped in 3a. Its
  `prepare_miner_thread`/`rx_set_miner_thread` (line 22) is
  miner-lifecycle, not verification-consensus, and is **not** an FFI
  export (spec §5); it is vestigial post-cutover but harmless and is
  removed with the `IPowSchema` abstraction in Phase 4.
- `src/crypto/pow_schema.h` (`IPowSchema`) — **kept** (Phase 4).

### 2.7 Corpus errata caught during the survey

1. **Spec §5 code block uses the decayed pointer form.**
   `RANDOMX_V2_RUST.md:315` declares
   `const uint8_t* seedhash32` / `uint8_t* out_hash32`, but the
   ratified Round-5 hardening (`RANDOMX_V2_PLAN.md` §5 lines 220-224,
   from `RANDOMX_V2_PHASE2C_PLAN.md` §14) mandates the **pointer-to-
   array** form `const uint8_t (*seedhash)[32]` / `uint8_t (*out)[32]`
   precisely because the decayed form silently re-admits the
   wrong-sized-buffer bug class the typed-array-pointer was added to
   prevent. Phase 3 implements the Round-5 form; the docs task (§12)
   corrects the §5 code block to match (erratum, not a design change).
2. **Line-number drift.** The pre-survey sketch's `rx_seedheights`
   and `rx_set_main_seedhash` line numbers were stale against
   `e63701676`; §2.2–§2.4 are the corrected inventory.

## 3. Architecture: v1-C → v2-Rust, pre-genesis

### 3.1 What changes

Today, for non-genesis blocks the daemon computes
`crypto::rx_slow_hash` (RandomX **v1**, `external/randomx`); for
genesis (`major_version == 1`) the `>= RX_BLOCK_VERSION (12)` guards
are false, so dispatch falls through to CryptoNight (via the registry
/ the `202612` fossil residue). After the cutover, **all** blocks —
genesis included — verify through the Rust RandomX **v2** verifier
(`shekyl_pow_randomx_v2_hash`), and CryptoNight is gone from the
consensus path. Miners run the v2 C library (`external/randomx-v2`,
full-dataset fast mode); the daemon verifies with the v2 Rust
light-cache verifier. The light==full equivalence of v2 is what makes
that split sound — the Hole-1 gate (§7) proves it.

### 3.2 Genesis identity is unchanged

This is the key de-risking finding. The genesis block is mined at
**difficulty 1** (`generate_genesis_block` →
`find_nonce_for_given_block(…, difficulty=1, height=0, NULL)` in
`cryptonote_tx_utils.cpp`). At difficulty 1 the PoW target is the
maximum 256-bit value, so the **first** nonce tried satisfies it
regardless of algorithm — the genesis nonce stays `GENESIS_NONCE`.
And the genesis **block id** is `Keccak(serialized header)`, which is
independent of the PoW longhash. Therefore:

- The genesis block id does **not** change.
- Coinbase/genesis-dependent E2E vectors ("frozen genesis tests")
  are very likely **unchanged**; 3b verifies rather than assumes.
- Genesis PoW *validation* still passes trivially (any longhash ≤ max
  target at difficulty 1).

The only tests that necessarily change are PoW-hash-specific ones
(`mining_parity.cpp`), which assert a particular algorithm's output.

### 3.3 Data flow (3a, flag-gated)

```
get_block_longhash / RandomXPowSchema::hash / get_altblock_longhash
        │  (seed_hash: crypto::hash, blob: bytes)
        ▼
  #ifdef SHEKYL_RANDOMX_V2_VERIFY        ── 3a flag (default ON in 3a)
        │                                  legacy path retained #else
        ▼
  shekyl_pow_randomx_v2_hash(&seed, blob, len, &out)   [shekyl-ffi]
        ▼
  CacheStore::lookup_or_derive(seed) ── memoized 256 MiB PreparedCache
        ▼
  compute_hash (light VM)  ──►  out (32 bytes)

tip advance ──► shekyl_pow_randomx_v2_set_canonical(&seed)  [3a]
        ▼  lookup_or_derive(seed)  (eager, synchronous, off hot path)
        ▼  CacheStore::set_canonical(arc)  (sticky-pin vs eviction)
```

## 4. The `set_canonical` mechanism (§5/§6/§13 amendment)

### 4.1 Why a second committed export

Spec §5 commits **one** export (`…_hash`) and lists
`set_main_seedhash` and `prewarm` as explicitly *not* exported (§5,
§6, §13). But the ratified sticky-eviction DoS mitigation
(`RANDOMX_V2_PLAN.md` Decision #6 line 183;
`RANDOMX_V2_PHASE2C_PLAN.md` §5.11.7) requires the `shekyl-ffi` shim
to **know the canonical seedhash** so `CacheStore` can protect it
from LRU eviction under an adversary interleaving 3+ seedhashes. The
shim is stateless C-ABI — it cannot "know" the canonical seedhash on
its own; only C++ block-handling code knows it. The signal mechanism
was never added to §5. `CacheStore::set_canonical` (built Phase 2f,
`cache_store.rs`) is the receiving end; the missing piece is the FFI
export that carries the signal. Phase 3 adds it.

This is the sanctioned revisit per §6's own clause ("if a future
design needs prewarm, it must propose a new design doc that revisits
this decision"). The amendment is **scoped**: it adds a synchronous
canonical-pin-with-eager-derive signal, and explicitly does **not**
re-admit the rejected designs — the inherited async
`rx_set_main_seedhash` state machine (background threads, reorg edge
cases, lifecycle calls) or the "fake-prewarm" pattern §6 warns
against.

Shipping genesis without this would leave a *specified* DoS
unmitigated, contradicting the [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc)
priority-1 (security) commitment; hence the export is wired in 3a so
the protection is live the moment guards drop in 3b.

### 4.2 FFI shape

Per spec §5's uniform shape and the Round-5 pointer-to-array form:

```c
/* seedhash is a pointer to a 32-byte array (NOT decayed const uint8_t*) */
int32_t shekyl_pow_randomx_v2_set_canonical(const uint8_t (*seedhash)[32]);
```

Return codes are a subset of the §17 taxonomy: `OK (0)`,
`ERR_NULL_PTR (-1)`, `ERR_CACHE_DERIVE_FAILED (-3)`,
`ERR_INTERNAL (-4)`. `ERR_DATA_TOO_LARGE (-2)` is not reachable (no
`data` argument). C++ call sites use the canonical
`uint8_t buf[32]; …&buf` pattern (parent §5 line 224).

### 4.3 Internal prewarm + sticky-pin

The shim performs, in order: (1)
`CacheStore::lookup_or_derive(seed)` — eager, synchronous derivation
of the 256 MiB `PreparedCache` (or a cache hit), returning the
`Arc<PreparedCache>`; (2) `CacheStore::set_canonical(arc)` —
sticky-pin so the canonical cache survives LRU eviction. The eager
derive is the **internal** prewarm the user direction sanctioned
(prewarm is forbidden as *FFI surface*, not as Rust-internal
behavior); moving canonical-cache management into Rust is the
[`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
forward cut.

### 4.4 Latency-profile change (named explicitly)

`rx_set_main_seedhash` kicked off **asynchronous** dataset init on a
background thread (`rx-slow-hash.c:389-408`). `set_canonical` does the
~150–200 ms Argon2d derivation **synchronously** on the calling
(tip-advance) thread. This is **off the validation hot path** (it
runs at tip advance, ~once per 2048-block epoch ≈ 2.84 days, per spec
§6) and is within spec §6's accepted 150–200 ms one-off budget. The
profile changes from "background async" to "synchronous at tip
advance"; it is not the lazy-cost-on-first-validation behavior the
naive slot-swap-only wiring would have produced (Hole 2). No
background threads, no reorg scheduling, no `max_dataset_init_threads`
— that complexity is deleted, not ported.

### 4.5 Amendment record (authored here; landed in §12 docs task)

- **§5** — add `shekyl_pow_randomx_v2_set_canonical` to the committed
  surface (now two functions); record §4.1's gap-closure rationale;
  correct the §5 code block to the Round-5 pointer-to-array form
  (§2.7 #1).
- **§6 / §13** — clarify that the prewarm prohibition is scoped to
  (a) the async cache-rebuild state machine and (b) the fake-prewarm
  pattern; a synchronous canonical-pin-with-eager-derive is the
  ratified DoS mitigation's delivery mechanism, not a prewarm in the
  rejected sense.

## 5. Seedheight caller survey (§5 discretionary disposition)

Spec §5 makes `shekyl_pow_randomx_v2_seedheight` discretionary —
exported "only if the C++ caller survey proves the call cannot be
eliminated or moved to a Rust caller cleanly." Survey (§2.3): every
`rx_seedheight`/`rx_seedheights` caller is C++ block-validation code
that resolves a seed *height* and is cleanly served by the C
`rx_seedheight`, which **stays until 3c** (§1.2 #2). The discretionary
criterion is therefore **not met**: do not export it in Phase 3.

*Reopen criterion (3c):* when `rx-slow-hash.c` is deleted, the C
`rx_seedheight` disappears and the export lands per spec §16 — the
exact early-block branch (`height <= SEEDHASH_EPOCH_BLOCKS +
SEEDHASH_EPOCH_LAG → 0`, else the power-of-2 mask form) plus the
required spec-vector test across the epoch boundaries. Note: the
`shekyl-pow-randomx::consensus` module holding
`SEEDHASH_EPOCH_BLOCKS = 2048` / `SEEDHASH_EPOCH_LAG = 64` (with the
power-of-2 `const _` assertion, spec §16) **does not exist yet** — it
is a 3c deliverable. Until then the C constants
(`rx-slow-hash.c:137-138`) are authoritative and unchanged.

## 6. Phase 3a — FFI export + flag-gated coherent swap

### 6.1 Deliverables

1. Add `shekyl-pow-randomx` as a dependency of `shekyl-ffi`.
2. `shekyl-ffi/src/pow_randomx_ffi.rs` — `shekyl_pow_randomx_v2_hash`
   (per spec §5/§17) and `shekyl_pow_randomx_v2_set_canonical` (§4),
   both with the Round-5 typed-array-pointer params,
   `catch_unwind`→`ERR_INTERNAL`, and the §17 null/`data_len` checks
   (`RANDOMX_BLOCK_TEMPLATE_MAX_SIZE = 2 MiB`, parent §5 line 237). A
   process-lifetime `CacheStore` (capacity-2 LRU) lives in this
   module (the spec §5 "shekyl-ffi may memoize internally" surface).
3. `src/shekyl/shekyl_ffi.h` — both prototypes (pointer-to-array
   form, with the discipline comment per parent §5 line 222) + the
   §17 error-code `#define`s.
4. Flag-gated coherent swap behind `SHEKYL_RANDOMX_V2_VERIFY`
   (default ON in 3a): the **three** `rx_slow_hash` consensus sites
   (§2.1) → `…_hash`, and the **four** `rx_set_main_seedhash` sites
   (§2.2) → `…_set_canonical`, as one coherent pair. `#else` retains
   the v1 legacy calls so the daemon is buildable both ways for the
   review window.
5. Activate the per-PR average per-hash latency CI gate (≤3.0×, parent
   §6 line 246).

### 6.2 Reviewer map

- **Consensus-affecting:** the three hash call-site swaps (§2.1) and
  the four `set_canonical` swaps (§2.2). These change what the node
  computes/pins. Highest review attention.
- **New Rust:** `pow_randomx_ffi.rs` (shim correctness: pointer
  checks, error mapping, `CacheStore` wiring).
- **Mechanical:** `Cargo.toml`/`Cargo.lock` dep add; header
  declarations.
- **Inert in 3a:** because all current blocks are `major_version`
  below `RX_BLOCK_VERSION`, the swapped sites are reached for genesis
  via the registry/longhash paths only after 3b drops the guards —
  see §6.3.

### 6.3 Consensus-neutrality of 3a

3a swaps the **implementation** behind the existing consensus
dispatch but does not change **which** path a block takes: the
`>= RX_BLOCK_VERSION` guards still gate RandomX-vs-CryptoNight in 3a.
For the existing v1 RandomX sites the swap changes the bytes (v1→v2),
but there is no live chain to diverge (pre-genesis), and the Hole-1
gate (§7) proves the v2 verifier matches the v2 miner library. The
**consensus cutover proper** (genesis → RandomX, CryptoNight gone) is
3b, when the guards drop.

## 7. Phase 3a Hole-1 gate — C-full vs Rust-light parity

### 7.1 The invariant, and why 2g did not cover it

The Rust verifier is **light-cache only** (256 MiB `PreparedCache`;
no dataset in the crate). Miners run the v2 C library in
**full-dataset** fast mode. RandomX guarantees light and full produce
identical hashes — but the Phase 2g differential harness compares
Rust-light vs C-**light** (`randomx-v2-sys` is light-only *by
design*). The full-dataset path has therefore **never** been
differentially checked against the Rust verifier. The cutover
invariant is exactly that check:

> For the v2 library at `aaafe71`, for every `(seedhash, blob)`:
> `shekyl_pow_randomx_v2_hash(seed, blob)` (Rust light)
> == `randomx_calculate_hash` over a **full dataset** (C full).

### 7.2 Test construction

A gated C++ test (built only with `BUILD_RANDOMX_V2_MINER_LIB=ON`,
which links `external/randomx-v2` @ `aaafe71`):

1. Build the C-full reference **deterministically** — not via
   `rx-slow-hash.c`'s async state machine (which races light/full),
   but directly: `randomx_alloc_cache` → `randomx_init_cache` →
   `randomx_alloc_dataset` → `randomx_init_dataset` →
   `randomx_create_vm(flags | RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2)`
   → `randomx_calculate_hash`. The `RANDOMX_FLAG_V2` inclusion is
   load-bearing (its omission was the PR #79 divergence).
2. Compare byte-for-byte against `shekyl_pow_randomx_v2_hash` over a
   fixed corpus that includes the **genesis** `(seedhash=genesis
   block hash, blob=genesis hashing blob)` case (spec §16) and
   several non-genesis blocks.
3. Pin at least one **miner-produced KAT**: a `(seedhash, blob,
   expected_hash)` whose `expected_hash` was captured from an actual
   full-dataset mining run (not an in-process `rx_slow_hash`), frozen
   as a vector. This closes the in-process-proxy gap — it proves
   "blocks real miners produce validate under the Rust verifier," not
   just "two in-process computations agree."
   **(Status: deferred.** The landed harness pins an in-process full-dataset
   KAT (`kFrozenKatHashHex`) instead; the separate-process miner-run KAT is
   tracked in FOLLOWUPS and targeted before the genesis freeze — see §13.)

Gating: a ctest label (e.g. `randomx_v2_full_parity`) in the
release-gate suite, **not** the per-PR fast gate (the full dataset is
2+ GiB and minutes to build).

### 7.3 Named risk — halt-on-red, not fix-the-test

This gate rests on one load-bearing assumption: **RandomX v2's
light==full property holds for the library at `aaafe71`.** If this
test ever comes back **unequal**, it is **not** a test bug to fix. It
is a discovery that the v2 library's light and full modes diverge —
which would mean the light-only Rust verifier **cannot validate
full-dataset-mined blocks at all**, invalidating the entire
verification architecture. Consequence-of-failure: **halt the
cutover and escalate** for an architecture rethink; do not patch the
test, do not proceed to 3b. (Probability is low — it is a core
algorithm property and the fork is non-divergent from upstream — but
the consequence is catastrophic, which is exactly why the gate
exists.)

## 8. Phase 3b — registry collapse + gate removal + genesis

### 8.1 Deliverables

1. **Registry collapse** (§2.6): `get_pow_for_height` → always
   RandomX; delete `pow_cryptonight.cpp` + CMake entry; drop
   `get_cryptonight_*` declarations.
2. **Longhash gates / fossils** (§2.4, §2.5): delete the two `202612`
   fossils; make seed resolution unconditional; remove the consensus
   `RX_BLOCK_VERSION` guards (call-replacement guards at
   `blockchain.cpp:587/709/1417/5589`; `rx_seedheights` guard-removal
   at `1765/1827/1985/2320`; `core_rpc_server.cpp:1965/2309/3534`
   unconditional; delete the dead-CN branch at
   `core_rpc_server.cpp:2031`). Leave the `#define` and the
   RPC-payment sites (§1.2 #1). Drop the 3a `SHEKYL_RANDOMX_V2_VERIFY`
   flag and the `#else` legacy path.
3. **Genesis** (§8.3).

### 8.2 Reviewer map

- **Consensus-affecting:** the dispatch collapse and every guard
  removal in §2.4 (these change which path genesis and all blocks
  take). Highest attention.
- **Deletions:** `pow_cryptonight.cpp`, the two fossils, the
  dead-CN RPC branch, the 3a flag/`#else`.
- **Mechanical:** declaration drops; CMake entry removal.
- **Rollback:** re-add the 3a flag default-OFF (restores the v1
  legacy path) — the 3a `#else` is the in-tree rollback artifact for
  the review window; once 3b deletes it, rollback is a revert of 3b.

### 8.3 Genesis verification + test updates

- Verify `GENESIS_NONCE` is unchanged (difficulty-1 reasoning §3.2);
  re-mine only if it somehow changes (it should not).
- Verify the coinbase / frozen-genesis E2E vectors are unchanged
  (§3.2); regenerate only the deltas, if any.
- `tests/.../mining_parity.cpp`: drop the CryptoNight parity test;
  route the RandomX parity assertion through the v2 FFI; the expected
  hash is the v2 value (reuse a §7 KAT where possible).

## 9. Test gates summary

| Gate | Cadence | Asserts |
|------|---------|---------|
| Hole-1 C-full vs Rust-light parity (§7) | release-gate (`randomx_v2_full_parity`) | the cutover invariant; **halt-on-red** |
| 2g differential (light-vs-light) | per-PR | Rust verifier ≡ C v2 light |
| Per-hash average latency ≤3.0× | per-PR (from 3a) | parent §6 line 246 |
| Build both flag states (3a) | per-PR | legacy v1 path stays buildable in 3a |
| `cargo fmt` / `clippy -D warnings` / `cargo test` | per-PR | [`45-rust-lint-checks`](../../.cursor/rules/45-rust-lint-checks.mdc) |
| Genesis identity (§8.3) | 3b | block id / coinbase vectors unchanged |
| Symbol-isolation `nm` on `shekyld` | Phase 3c | parent §7 (deferred) |

## 10. Risks

1. **light==full assumption (§7.3)** — load-bearing; failure ⇒ halt
   + escalate, not a test fix. The single highest-consequence item.
2. **FFI / `Cargo.lock` churn** — Track B touches the FFI boundary
   and `Cargo.lock`; coordinate with concurrent wallet-stack work
   (parent §14 wallet-V3.2 gate). The user has elected to proceed
   ahead of that gate; this is the accepted contention cost.
3. **Built-in miner perf** — the daemon's internal miner now searches
   nonces through the Rust interpreter (no JIT). Acceptable for
   testnet/regtest low difficulty; not a consensus concern. Noted,
   not mitigated.
4. **Corpus errata (§2.7)** — the §5 decayed-pointer code block and
   stale line numbers were caught and corrected here; the docs task
   (§12) lands the §5 erratum so the spec and implementation agree.

## 11. Forward-actions / deferred (A5)

- **FOLLOWUPS additions:** RPC-payment subsystem deletion (V3.0
  pre-genesis); `RX_BLOCK_VERSION` `#define` deletion (bundled with
  RPC-payment / Phase 4); `shekyl_pow_randomx_v2_seedheight` export +
  `shekyl-pow-randomx::consensus` module (3c); `rx-slow-hash.c` /
  `slow-hash.c` deletion (3c, blocked by RPC-payment + `wallet2.cpp`).
- **Spec amendments (§12):** `RANDOMX_V2_RUST.md` §5/§6/§13 per §4.5.
- **Phase 4:** `IPowSchema`/`pow_registry` abstraction deletion;
  `prepare_miner_thread`/`rx_set_miner_thread` removal.

## 12. Documentation updates (final task)

Per [`91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc):

- `CHANGELOG.md` — PoW cutover entry.
- `RANDOMX_V2_PLAN.md` — Track B Phase 3 status; record 3a/3b split.
- `RANDOMX_V2_RUST.md` — §5/§6/§13 amendments (§4.5) and the §5
  code-block erratum (§2.7 #1).
- `docs/FOLLOWUPS.md` — the §11 deferred items, each with a target
  version.
- `USER_GUIDE` / `DESIGN_CONCEPTS` PoW sections — only if touched.

## 13. Status — landed (2026-06)

The consensus PoW cutover (3a + 3b) is complete. 3c is deferred.

**3a — FFI export + Hole-1 gate (flag-gated):**
- `shekyl-pow-randomx` dep + `pow_randomx_ffi.rs`; `shekyl_ffi.h` decls
  for `…_hash` and `…_set_canonical` (Round-5 pointer-to-array shape).
- Flag-gated (`SHEKYL_RANDOMX_V2_VERIFY`) coherent swap at the hash site
  + 4 `set_canonical` sites; legacy v1 path stayed buildable.
- Hole-1 differential gate (`tests/randomx_v2_parity/randomx_v2_full_parity.cpp`):
  C v2 full-dataset ≡ Rust v2 light-cache over a corpus + an **in-process**
  full-dataset frozen KAT (`kFrozenKatHashHex`); halt-on-red. The frozen KAT
  is captured from the harness's own full-dataset computation, **not** from a
  separate-process mining run; that end-to-end miner-provenance KAT is deferred
  (tracked in FOLLOWUPS, targeted before the genesis freeze). Worked around the
  vendored-library teardown double-free (`_Exit`, also tracked in FOLLOWUPS).

**3b — collapse to RandomX-only (consensus cutover):**
- `383b560f1` — `get_pow_for_height` collapsed to RandomX for every
  version; `pow_cryptonight.cpp` + CMake + `get_cryptonight_*` deleted;
  `mining_parity.cpp` rewritten (CN tests dropped, RandomX routed via the
  v2 FFI against the Hole-1 KAT).
- `1e9389e19` — `SHEKYL_RANDOMX_V2_VERIFY` flag removed (unconditional v2).
- `1a7650c29` — all `RX_BLOCK_VERSION` consensus guards removed; both
  longhash-`202612` fossils + the dead-CN RPC branch deleted; seed
  resolution made unconditional. `get_block_longhash` collapsed to a
  direct v2 call.
- `c1611f4be` (same-file cleanup) — `calculate_block_hash`
  block-id-`202612` fossil removed; vestigial `blob` param dropped.
- `6ae9c0643` — **genesis identity gate.** §3.2 verified empirically, not
  assumed: per-net `nonce == GENESIS_NONCE` (difficulty-1 invariant) and
  frozen genesis block ids (mainnet `919f8db5…`, cross-checked against the
  daemon-captured height-0 `block_hash` in
  `rust/shekyl-wire/tests/vectors/regtest_coinbase_hashes.json`). The
  Rust `coinbase_hash` / `coinbase_roundtrip` frozen vectors needed **no**
  regeneration — the feared frozen-genesis E2E rework was unnecessary.

**Gate status (§9):** Genesis identity — **met** (`6ae9c0643`). Hole-1
parity — armed (release gate). The Phase-3c-only gates (symbol-isolation
`nm`, seedheight spec-vector) remain deferred with the C-file deletions.

**3c — deferred** (blocked by RPC-payment subsystem deletion +
`wallet2.cpp` PoW touchpoints; tracked in `docs/FOLLOWUPS.md`): delete
`rx-slow-hash.c` + `slow-hash.c`, drop the `cncrypto` randomx C linkage,
export `shekyl_pow_randomx_v2_seedheight` + add the
`shekyl-pow-randomx::consensus` module (`SEEDHASH_EPOCH_BLOCKS`/`_LAG`),
and add the CI symbol-isolation invariant.
