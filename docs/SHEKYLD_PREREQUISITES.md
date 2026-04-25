# `shekyld` Prerequisites for the V3 Wallet Rust Rewrite

This document consolidates the Phase 0 audit of `shekyld` (the Shekyl
daemon) against the prerequisites declared by the
[V3 wallet Rust rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md).
The plan's later phases assume specific daemon-side capabilities; this
document records what exists, what does not, and what (if anything)
must be filed as a separate daemon-side follow-up before the
dependent wallet phase can proceed.

The file is **plural** (`PREREQUISITES`, not `REGTEST` / `FEE_ESTIMATES`)
so future Phase 0 audits can append rather than spawn new files. New
audits go in their own top-level section at the bottom of the file.

**Output of:** PR 0.3 of the rewrite plan.
**Audit date:** 2026-04-25.
**Scope:** the daemon binary `shekyld` and its JSON-RPC surface as it
exists on `dev` at this date. Wallet-side code (`wallet2.cpp`,
`shekyl-wallet-*` Rust crates) is referenced only as evidence of what
the daemon currently exposes; wallet-side rework belongs to the
Phase 1+ rewrite, not to this audit.

---

## 1. Instant-mining regtest mode (Phase 6 prerequisite)

### Verdict: PRESENT — usable, with V3-specific caveats

`shekyld` inherits Monero's `FAKECHAIN` network type, the `--regtest`
CLI flag, the `generateblocks` JSON-RPC method, and the
`--fixed-difficulty` knob. A Rust integration-test harness can spawn
`shekyld` and drive an end-to-end transfer cycle without waiting for
real-network PoW, but several Shekyl-genesis differences mean the
regtest path is **not** a free pass on V3 consensus rules.

### What works today

**Network type.** `FAKECHAIN` is a first-class enum variant alongside
`MAINNET` / `TESTNET` / `STAGENET`
(`src/cryptonote_config.h:297–305`). When constructed, `FAKECHAIN`
borrows mainnet constants for genesis, ports, and network id
(`src/cryptonote_config.h:338–343`).

**CLI activation.** Passing `--regtest` to `shekyld` sets
`m_nettype = FAKECHAIN` (`src/cryptonote_core/cryptonote_core.cpp:472–475`).
The flag is mutually exclusive with `--testnet` / `--stagenet`
(`src/daemon/main.cpp:267–273, 329–330`). Companion flags:

- `--fixed-difficulty <N>` — pin difficulty to a constant. Default `0`
  means "use adaptive difficulty," so for instant-mining the harness
  must pass `--fixed-difficulty 1` (or another small value)
  (`src/cryptonote_core/blockchain.cpp:895–897, 1263–1265`).
- `--keep-fakechain` — preserve LMDB across runs; without it, the DB
  is wiped each launch (`src/cryptonote_core/cryptonote_core.cpp:531–538`).
- `--offline` — disable peer dialing (recommended for hermetic tests).
- `--disable-dns-checkpoints` — disable upstream checkpoint fetch.

**On-demand block generation.** The JSON-RPC method `generateblocks`
exists (`src/rpc/core_rpc_server.h:153`,
`src/rpc/core_rpc_server.cpp:2234–2305`). It loops
`getblocktemplate` → `find_nonce_for_given_block` (RandomX longhash) →
`submitblock` for the requested count. The handler refuses with
`CORE_RPC_ERROR_CODE_REGTEST_REQUIRED` outside `FAKECHAIN`
(`src/rpc/core_rpc_server.cpp:2242–2246`), and the RPC map gates it on
`!m_restricted` (`src/rpc/core_rpc_server.h:153`), so the integration
harness must connect to an unrestricted RPC port.

**Proof-of-life tests.** Existing Python functional tests
(`tests/functional_tests/blockchain.py`, `daemon_info.py`,
`transfer.py`, `mining.py`, `p2p.py`) drive `--regtest` against
`generateblocks`. The launch script
`tests/functional_tests/functional_tests_rpc.py:37–77` demonstrates a
working invocation pattern.

### Working CLI invocation

```bash
shekyld \
  --regtest \
  --offline \
  --fixed-difficulty 1 \
  --disable-dns-checkpoints \
  --data-dir /tmp/shekyl-regtest-XXXX \
  --rpc-bind-port 28081 \
  --p2p-bind-port 28080 \
  --no-zmq
```

Use `--keep-fakechain` if you want the chain to persist across daemon
restarts within a single test run.

### V3-specific caveats

**FCMP++ tx-type enforcement is bypassed on `FAKECHAIN`.**
`src/cryptonote_core/blockchain.cpp:3403–3434` wraps the
`RCTTypeFcmpPlusPlusPqc` enforcement, version bounds, and input-count
limits in `if (m_nettype != network_type::FAKECHAIN) { ... }`. Regtest
will accept legacy/test-generator txs that would be rejected on
mainnet. **Implication:** regtest is suitable for harnessing wallet
flows end-to-end, but a regtest-green wallet test does not by itself
prove the wallet builds valid V3 transactions for mainnet. The Rust
integration tests must explicitly construct FCMP++ transactions and
verify them against mainnet rules in a separate test layer (e.g.,
KAT-driven validation of the proof bytes).

**`curve_tree_root` header field is not checked on `FAKECHAIN`.**
`src/cryptonote_core/blockchain.cpp:4810–4824` wraps the
header-vs-DB curve-tree-root comparison in
`if (new_height > 0 && m_nettype != FAKECHAIN)`. Regtest blocks can
carry placeholder roots; per the comment at 3656–3657, FCMP++
verification still uses `m_db->get_curve_tree_root_at_height`, so
proof verification itself remains rigorous, but block-header coherence
of the curve-tree root is a separate property regtest does not
exercise.

**FCMP++ reference-block age rules still run.**
`src/cryptonote_core/blockchain.cpp:3620–3652` is **not** wrapped in a
`FAKECHAIN` skip. V3 spends must reference a curve-tree root from a
sufficiently-aged block, in regtest just as on mainnet. The harness
must therefore mine enough blocks before constructing test transfers
for the curve-tree state to be valid; "spawn daemon, build tx
immediately" will fail validation.

**PoW is not bypassed.** `check_hash` runs in the block path
(`src/cryptonote_core/blockchain.cpp:4445–4451`). With
`--fixed-difficulty 1` the work is trivial (microseconds per block on
modern hardware), but the path is exercised. There is no separate
"skip PoW" toggle.

**Regtest hard-fork table.**
`src/cryptonote_core/cryptonote_core.cpp:674–678` defines
`regtest_hard_forks` to force HF1 at height 0, then jump to the latest
mainnet HF version at height 1. Regtest activates V3 rules from the
first non-genesis block.

### Pre-existing harness gaps (not blocking, but worth filing)

The Python functional tests under `tests/functional_tests/` still
invoke binaries named `monerod` and `monero-wallet-rpc`
(`tests/functional_tests/functional_tests_rpc.py:37–77`,
`tests/README.md:60–64`), and embed Monero-format addresses
(`42ey...`). The Shekyl-renamed binaries are `shekyld` and
`shekyl-wallet-rpc` (`src/daemon/CMakeLists.txt:74`,
`src/wallet/CMakeLists.txt:98`). The Rust integration harness
(`tests/integration/wallet_e2e/` per the rewrite plan) will spawn
`shekyld` directly — this gap does not block the rewrite, but the
Python functional suite is itself dead weight that the rewrite's
deletion phase will sweep up.

### Pre-task verdict (regtest)

**No `shekyld` change required for Phase 6 to start.** The Rust
integration harness can be built against the existing `--regtest` +
`generateblocks` surface. The V3-specific caveats above are
test-design constraints (mine enough blocks for curve-tree validity,
do not assume `FAKECHAIN` enforces V3 tx-type rules) rather than
daemon bugs that need fixing first.

---

## 2. `get_fee_estimate(s)` daemon RPC (Phase 2a prerequisite)

### Verdict: PRESENT — singular `get_fee_estimate`, positional 4-slot fee vector, no name-keyed buckets

`shekyld` exposes a JSON-RPC method named `get_fee_estimate`
(singular). Its response is **not** a single value; it returns a
4-element `fees` vector representing the four 2021-scaling tiers,
plus a duplicate `fee` field (= `fees[0]`) and a
`quantization_mask`. The vector is **positional** — the wire format
does not carry string names like `{"slow": ..., "normal": ...}`. The
priority-name layer lives on the wallet side (currently
`fee_priority::{Unimportant, Normal, Elevated, Priority}` in
`src/wallet/fee_priority.h:14–21`), mapping to indices 0–3.

### Wire shape

`src/rpc/core_rpc_server_commands_defs.h:2245–2271`:

```cpp
struct COMMAND_RPC_GET_BASE_FEE_ESTIMATE
{
  struct request_t : public rpc_access_request_base {
    uint64_t grace_blocks;
    // ...
  };
  struct response_t : public rpc_access_response_base {
    uint64_t fee;
    uint64_t quantization_mask;
    std::vector<uint64_t> fees;
    // ...
  };
};
```

Internal C++ name: `COMMAND_RPC_GET_BASE_FEE_ESTIMATE` /
`on_get_base_fee_estimate`. JSON-RPC method name on the wire:
`get_fee_estimate` (`src/rpc/core_rpc_server.h:173–174`).

### Filling logic

`src/rpc/core_rpc_server.cpp:2987–3008`. Because Shekyl's
`HF_VERSION_2021_SCALING` is `1` (i.e., Shekyl genesis is already in
the post-2021-scaling regime — confirmed in `cryptonote_config.h`),
the `fees` vector is **always** populated with the four tiers by
`get_dynamic_base_fee_estimate_2021_scaling`. The legacy
single-`fee` branch is dead code on Shekyl from genesis.

### Tier semantics

`src/cryptonote_core/blockchain.cpp:3853–3857`:

```cpp
fees.resize(4);
fees[0] = round_money_up(Fl, ROUNDING_PLACES);   // lowest
fees[1] = round_money_up(Fn, ROUNDING_PLACES);
fees[2] = round_money_up(Fm, ROUNDING_PLACES);
fees[3] = round_money_up(Fh, ROUNDING_PLACES);   // highest
```

The four entries correspond to the 2021-scaling document's `Fl`,
`Fn`, `Fm`, `Fh` tiers; they are **not** wallet-priority-named on the
wire.

### Existing wallet-side mapping

The C++ wallet maps fee priority to a fee-vector index in
`wallet2::get_base_fee` (`src/wallet/wallet2.cpp:7985–8005`):

```cpp
uint64_t wallet2::get_base_fee(fee_priority priority) {
  priority = fee_priority_utilities::clamp_modified(priority);
  priority = fee_priority_utilities::decrease(priority);
  std::vector<uint64_t> fees;
  m_node_rpc_proxy.get_dynamic_base_fee_estimate_2021_scaling(
      FEE_ESTIMATE_GRACE_BLOCKS, fees);
  // ...
  return fees[fee_priority_utilities::as_integral(priority)];
}
```

The five-level enum (`Default`, `Unimportant`, `Normal`, `Elevated`,
`Priority`) compresses to four after `Default` → bucket-map and
`decrease` clamps; the four non-default levels then index `fees[0..3]`
directly.

### Hardcoded multiplier table is dead code

`src/wallet/wallet2.cpp:7919–7961` defines `get_fee_multiplier` with a
hardcoded `fee_steps` table per fee algorithm. Repo-wide grep
confirms this method has **no live callers** in the active transfer
path (`create_transactions_2` at `wallet2.cpp:9144–9145` uses
`get_base_fee(priority)` directly). The multiplier table is residue
from pre-2021-scaling fee logic and is functionally inert. It is
included in the Phase 5 deletion sweep along with the rest of
`wallet2.cpp`.

### Pre-task verdict (fee-estimate RPC)

**No `shekyld` change required for Phase 2a to start.** The Rust
wallet's `Wallet::send` can call `get_fee_estimate` and consume
`fees[0..3]` directly. The wallet-side decision log already records
the priority-name binding: `Economy = fees[0]`, `Standard = fees[1]`,
`Priority = fees[3]`, with a `Custom(u64)` escape hatch for explicit
per-byte fee in atomic units. (The plan's prior wording referred to
"named per-bucket fee estimates from the daemon"; this audit confirms
that names are wallet-side, not wire-side. The decision is unchanged
in substance — daemon supplies the numbers, wallet supplies the
names — but the implementation now binds names to known positional
indices rather than parsing them from a daemon-supplied map.)

The wallet-side sanity ceiling
(`TxError::DaemonFeeUnreasonable`) remains binding: any
`fees[i]` that exceeds a wallet-configured maximum (denominated in
atomic units / byte) causes the wallet to refuse the build with a
typed error. The ceiling itself is wallet config, not daemon config.

---

## 3. Fee policy / rules version exposure

### Verdict: ABSENT — file as daemon-side follow-up, NOT a Phase 0 blocker

`shekyld` does not expose a fee policy version in any form. There is
no `fee_version` field on `get_fee_estimate`'s response, no
`fee_policy_id` on `get_info`, and no separate `get_fee_policy_version`
RPC. The closest available signals are the daemon binary version
(`get_version` JSON-RPC) and the consensus hard-fork metadata
(`hard_fork_info` JSON-RPC), neither of which is a fee-rules epoch.

### Evidence of absence

**`get_fee_estimate` response:** the struct at
`src/rpc/core_rpc_server_commands_defs.h:2245–2271` contains `fee`,
`quantization_mask`, `fees`, and the inherited
`rpc_access_response_base` (status, untrusted, etc.). No version
field.

**`get_info` response:** the struct at
`src/rpc/core_rpc_server_commands_defs.h:676–778` contains height,
difficulty, daemon version, protocol version, Shekyl-NG economics
fields, peer counts. No `fee_version` / `fee_policy_id`.

**No dedicated RPC.** Repo-wide grep over `src/rpc/` for
`fee_version` / `fee_policy` / `fee_rules_version` returns no results
in any RPC definition file (`core_rpc_server.h`,
`core_rpc_server_commands_defs.h`, `core_rpc_ffi.cpp`).

### Why this matters and why it is deferrable

The wallet's `Wallet::send` path needs to know what fee rules apply
when building a transaction. If `shekyld` later changes its fee
policy (different base-fee math, different per-bucket scaling rules,
a network-level fee market change activated at hard fork), the wallet
needs a way to detect "this daemon's fee policy is newer than I know
about" and refuse to build until the wallet code understands the new
rules. Without that signal, the wallet either silently builds against
stale assumptions or has to over-pay to a hand-cranked safety margin.

For V3.0 launch, this gap is **not blocking**. V3.0 launches with
whatever fee policy `shekyld` has at that moment, and any subsequent
fee-policy change happens via hard fork; the wallet binary is rebuilt
and redeployed against the new `shekyld` at fork time. The wallet
binary version itself is implicitly the fee policy version for that
launch cycle.

After V3.0, when the fee policy is potentially upgraded
mid-version-cycle (e.g., a fee-market parameter tuning at a future
hard fork), the absence of an explicit `fee_version` becomes
load-bearing. The wallet would then have no in-band way to detect
that the daemon's rules changed unless the wallet binary version is
strictly synchronized with the daemon binary version, which is a
deployment constraint that is fine for the CLI but awkward for
GUI/mobile wallets that ship on slower update cycles.

### Recommendation

File a daemon-side follow-up at `docs/FOLLOWUPS.md` under the V3.1+
section (alongside the `wallet2.cpp` rewrite scope and the typed
LMDB transactional wrapper):

> **`shekyld` fee policy version exposure.** Add a
> `fee_policy_version: u32` field to either `get_fee_estimate`'s
> response or `get_info`'s response (preference: `get_fee_estimate`,
> since the version is logically scoped to fee semantics). The field
> increments any time the fee math, the per-bucket scaling rules, or
> the priority-to-bucket mapping changes. The Rust wallet detects
> "version > known_max_version" at refresh time and refuses to
> build new transactions until the wallet binary is updated, with a
> clear typed error (`TxError::DaemonFeePolicyUnknown { observed,
> known_max }`). Target version: V3.1.

The wallet rewrite plan does **not** wait for this. Phase 2a builds
its fee logic against the current 4-tier positional response and
treats the field as `Option<u32>` for forward compatibility — the
wallet sends a `fee_policy_version` in its config and refuses
transactions if the daemon ever returns a value strictly greater. If
the daemon never adds the field, the option stays `None` and the
wallet behaves as today. If the daemon adds the field in V3.1, the
wallet starts honoring it without a wire-format break.

---

## 4. Summary table

| Prerequisite                   | Verdict   | Phase blocked | Daemon change needed? |
|--------------------------------|-----------|---------------|-----------------------|
| Instant-mining regtest mode    | PRESENT   | Phase 6       | No                    |
| `get_fee_estimate` RPC         | PRESENT   | Phase 2a      | No                    |
| Fee policy / rules version     | ABSENT    | (post-V3.0)   | Yes — V3.1 follow-up  |

**Phase 0 release gate verdict.** All three audit items resolve
favorably for the rewrite plan. Phase 6 (integration tests) and
Phase 2a (`Wallet::send`) can proceed against the existing daemon
surface. The fee-policy-version absence is filed as a V3.1 daemon-side
follow-up, not a Phase 0 blocker — Phase 2a builds a forward-compatible
client that gracefully consumes the field if it appears later.

---

<!-- Append new Phase 0 audits below this line, each as its own ## section. -->
