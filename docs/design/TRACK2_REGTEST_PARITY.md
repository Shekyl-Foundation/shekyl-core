# Track 2 — End-to-end FAKECHAIN regtest: C++↔Rust FCMP++ verify parity

**Status:** In progress (started 2026-06-20). Phase 0 (harness) landed and green;
Phase 1 (transfer keystone) next. **Authoritative spec for:** the wallet↔daemon
submit/verify parity surface. **Parent:** [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md)
§9 ("C++" row + CT-2 Tier-B), [`CT5_ROUND1_CLOSEOUT.md`](../completed/CT5_ROUND1_CLOSEOUT.md)
§6 (Track 2 is downstream of CT-5, not part of it).

---

## 1. Context — what this proves

CT-5 proved the Rust wallet can build a spend whose FCMP++ proof verifies against
a **Rust-reconstructed** tree, in-process (PR #162). Track 2 proves the **submit
direction against a live daemon**: a wallet-built proof, serialized into a tx and
sent over the real RPC transport, is accepted by `shekyld`'s consensus
`shekyl_fcmp_verify` against the daemon's own per-height curve-tree root.

- **Ingest/reconstruct parity is already proven** offline: `recon_kat.rs` (Tier-A)
  replays `ct2_tier_a.json` (generated from a live regtest) and asserts wallet
  `build_layers` root == daemon header root at every height.
- **Submit/verify parity is the new surface.** The verify code is the same Rust
  `shekyl_fcmp::proof::verify` the daemon calls via FFI
  (`shekyl_ffi.h:368` → `shekyl-ffi/src/lib.rs:1485`), and the wallet and daemon
  also share the tree-construction FFI (`grow_curve_tree` → `shekyl_curve_tree_*`).
  So parity is **structural** — the in-process #162 result should carry to the
  daemon by transitivity.

**Where a Phase-1 failure will hide.** Because verify, the root, and tree
construction are shared FFI, a failure is almost certainly in the one surface the
shared code does **not** cover: the **tx-blob serialize↔parse round-trip** (Rust
serializes the FCMP++ proof + reference into the tx; C++ `cryptonote_basic`
parses it and hands bytes back to verify) and the **independently-computed PQC
prehash** (`serialize(TransactionPrefixV3) || serialize(RctSigningBody) ||
H(serialize(RctSigPrunable))` on each side). Look there first.

This unblocks CT-2 Tier-B (`recon_tier_b.rs`'s 5 `#[ignore]`d tests need a real
regtest spend path) and the depth-3+ verify validation deferred by #162.

## 2. What already exists (verified) vs. the gaps

| Capability | Where | Status |
|---|---|---|
| FAKECHAIN net mode, ephemeral `/fake` datadir | `cryptonote_config.h:328-335,372`, `cryptonote_core.cpp:472-539` | exists |
| `generateblocks` (FAKECHAIN-gated) + `pop_blocks` | `core_rpc_server.cpp:2259` | exists |
| `--fixed-difficulty` (instant mining) | `cryptonote_core.cpp:94`, `blockchain.cpp:1008` | exists |
| Live header carries **real** root; per-height root table written on add-block | `blockchain.cpp:1959-1961`, `blockchain_db.cpp:453-458` | exists |
| Daemon `shekyl_fcmp_verify` == Rust `verify` via FFI; pool + block-accept | `blockchain.cpp:3998/4126`, `tx_pool.cpp:239` | exists |
| Production `DaemonClient` (HTTP JSON-RPC): block fetch, fee, submit→verdict | `engine/daemon.rs:231-285` | exists |
| Block→curve-tree ingest + verify-at-ingest vs header root | `engine/merge.rs:397,568` | exists |

**Gaps (the Track-2 build):** (1) no Rust harness that spawns `shekyld` and drives
the production `Engine` against it (engine tests used the `TestDaemon` mock);
(2) no end-to-end mint→spend→submit→verify test; (3) depth-3+ verify never
exercised; (4) `ct2_tier_b.json` not generated, `recon_tier_b.rs` `#[ignore]`d.

## 3. Plan (phased; stacked PRs — see §7)

### Phase 0 — `RegtestDaemon` harness (DONE, green)
Spawn `shekyld --regtest --offline --non-interactive --fixed-difficulty 1
--rpc-bind-port <ephemeral> --data-dir <temp>`; poll `get_info` for readiness;
`generate_blocks`/`pop_blocks`/`get_info` over `SimpleRequestRpc`; kill + clean on
`Drop`. **Placement:** internal `#[cfg(test)]` module
`shekyl-engine-core/src/engine/regtest_e2e.rs` (not a `tests/` crate) — it needs
crate-internal visibility for the serialize/parse + reanchor assertions, and the
wallet uses `Network::Mainnet` (FAKECHAIN = mainnet address format) which the
`#[cfg(test)] pub(crate)` `for_test_full` helper does not cover. All tests
`#[ignore]`d, binary via `SHEKYLD_BIN`. Serialized through one async lock (cargo
test is parallel) + scoped stale-daemon sweep.

### Phase 1 — Transfer keystone
Mint coinbase to the wallet address, mature (`+60`), `Engine` refresh (scan +
build tree; verify-at-ingest now runs against a **live** daemon), build a
single-input transfer, submit via `DaemonClient`. **Assert both consensus verify
points:** `Submitted` (pool verify) AND confirmation after `generate_blocks(1)`
(block-accept verify) — on a live net these can use different reference roots.
Fold the two CT-5d reanchor cases here (a static-tip build→submit never ages the
reference, so they otherwise never fire):
- **(a) reprove** — `generate_blocks(REBUILD_AT+)` between build and submit → the
  tip-advance reanchor fires → daemon accepts the reanchored proof.
- **(b) ReselectionRequired** — `pop_blocks` a reorg below the reference between
  build and submit → consumer rebuilds → resubmits → accept; measure firing rate.

### Phase 1b — Bond gate (separate, after the transfer keystone is green)
The bond-post path is `O~`-exposed (vin-layer ML-DSA equality is unlanded
C-1/C-2), so a bond failure can be orthogonal to parity. **Confirm the daemon's
bond-post verify dispatch (`verRctSemanticsBondPost` / membership-only) is
landed+stable on current dev before running**, and never let bond block the
transfer milestone. Requires rebasing the worktree onto current dev (#163
archival-bond merged).

### Phase 2 — depth-3+ verify (Tier-B PR)
Mint enough outputs to grow past depth-2 (> `SELENE_CHUNK_WIDTH=38` matured
leaves). **Drive by observed tree depth (poll the root table), not a hardcoded
height** — the budget is maturity-bound (~38 + 60 ≈ ~100 coinbase blocks).
Confirm regtest RandomX mode/cost and budget the CI timeout.

### Phase 3 — Tier-B fixture + un-ignore `recon_tier_b` (Tier-B PR)
Extend `gen_ct2_fixture.py` (reuse its `Daemon` driver) → `ct2_tier_b.json`:
multi-tx block, **mixed-maturity collision** (`+10` regular vs `+60` coinbase at
the same height), staked output (tag `0x4`), reorg-with-spend. Hand-craft the
adversarial `tx_extra 0x07` oracle separately (no regtest). Un-ignore the 5 tests.

### Phase 4 — Closeout (Tier-B PR)
CT-2 Tier-B row + close the CT-5d reanchor FOLLOWUPs and fire the reselect
reopening trigger; CHANGELOG.

## 4. Design pins / decisions

- **Verify-parity is structural; the real surface is serialize/parse.** A
  serialize/parse or PQC-prehash mismatch is a **genesis-frozen wire-format
  arbitration**, not a behavioral bug: decide the canonical byte layout
  deliberately, then make both sides match it — do **not** auto-default to the
  Rust side. (Transport-layer mismatches — RPC envelope, Content-Type — are *not*
  this and are fixed Rust-side; see §6.)
- **Transfer is the keystone; bond is a separate gate.** Transfer rides the
  settled membership path; bond rides the `O~`-exposed path. Sequence so a bond
  failure surfaces the `O~`/routing gap without blocking the transfer milestone
  (the real unlock for Tier-B + depth-3+).
- **Reorg failures are daemon-rollback-first.** The reorg cases are the first live
  exercise of the daemon's `pop_block` deferred-insertion tree rollback (popping
  H removes leaves from outputs created at H−maturity). Diagnose the daemon
  rollback / LMDB-atomicity path before suspecting wallet `ReselectionRequired`.
- **X3 ordering parity is first testable at mixed maturity.** `gindex ==
  global_output_index` trivially (both creation order). The consensus-relevant
  ordering is the tree leaf position = **drain order `(maturity, gindex)`**
  (`client.rs:326`). A single maturity class collapses it to gindex, so
  coinbase-only Tier-A and the Phase-1 coinbase spend cannot expose a divergence;
  the Phase-3 mixed-maturity fixture is the first real test. **Prerequisite:**
  confirm at source that the daemon's `grow_curve_tree` defers insertion to
  `eligible_height` the same way the wallet drains.
- **Tier-B fixture captures the deterministic projection only** (per-height roots,
  leaf-identity→gindex) — never raw tx blobs (real spends carry random
  blinds/keys/shuffle). The reorg-with-spend scenario is a fixed scripted sequence
  so its roots reproduce even though its txs do not.

## 5. Sequencing

Stacked PRs: **keystone PR** = Phase 0 + 1 (transfer-first, then the gated bond,
plus the two reanchor cases) → **Tier-B PR** = Phase 2 + 3 + 4. Phase 1 is where
the unknowns are; it gets a **hard checkpoint** (green + reviewed) before the
fixture generator and depth-3+ build on top.

## 6. Findings log (real bugs surfaced)

The wallet↔daemon RPC transport had never been run end-to-end (production only
pointed `SimpleRequestRpc` at dummy URLs). Three incompatibilities between the
vendored monero-oxide client and our axum `shekyl-daemon-rpc` server — all
**transport, not consensus**, so Rust-side fixes are correct:

1. Base URL must omit `/json_rpc` (`json_rpc_call` appends the route). [harness]
2. Client sent no `Content-Type`; the axum server requires it. Fixed in
   `simple-request::inner_post` (`application/json`; `*.bin` → `octet-stream`).
3. Client sent a non-compliant JSON-RPC envelope (no `id`/`jsonrpc`); the server
   requires `id`. Fixed in `Rpc::json_rpc_call` to emit a compliant 2.0 envelope.

(2) and (3) edit vendored `shekyl-oxide` RPC code (protocol code, ours per rule
10) and diverge from the stale `monero-oxide@3933664d` pin.

4. **`get_curve_tree_path` returns 404 under the Rust/Axum daemon RPC.** The
   C++ `on_get_curve_tree_*` handlers exist and are registered in the legacy
   epee dispatch but are missing from the Axum/FFI JSON-RPC dispatch table
   (`src/rpc/core_rpc_ffi.cpp` `get_jsonrpc_table()`), so the wallet's
   curve-tree path fetch 404s when the daemon runs the default Rust RPC server.
   Handler-side bugs also surfaced (immature outputs must be skipped, not
   errored; branch-layer count loop is `<= tree_depth`). Surfaced 2026-06-21
   debugging the C++ FCMP++ spend path; the exploration was reverted as
   out-of-scope C++ debt. Both the dispatch gap and the spend-path findings the
   Rust send-path must reproduce are tracked in
   [`FOLLOWUPS.md`](../FOLLOWUPS.md) — "Rust/Axum daemon RPC: curve-tree
   endpoints missing from the FFI dispatch table" and "C++ FCMP++ wallet send
   path incomplete".

### In-process Rust FCMP++ spend validation (no daemon)

Independent of this daemon-parity harness, `shekyl-wire/tests/fcmp_spend_e2e.rs`
now builds a full FCMP++ spend from real crypto (depth-3 curve tree, FCMP++
proof, CT balance, Bulletproof+ range proof, PQC auths) entirely in-process
and asserts byte-identical `shekyl-wire` serialization round-trip. It replaced
the unsound C++-oracle byte-identity KAT (which depended on a spend blob the
non-functional C++ spend path could never emit). This validates the Rust
consensus + wire stack without a running daemon; the daemon-parity gap above is
what still needs the RPC dispatch wiring before an end-to-end wallet→daemon
spend can run.

## 7. Verification

From `rust/`, with `shekyld` built from current dev:
```bash
cargo fmt --all -- --check
cargo clippy -p shekyl-engine-core -p shekyl-curve-tree --all-targets -- -D warnings
SHEKYLD_BIN=/abs/build/bin/shekyld \
  cargo test -p shekyl-engine-core --lib regtest_e2e -- --ignored --nocapture   # Phase 0/1/1b/2
cargo test -p shekyl-curve-tree --test recon_tier_b                              # Phase 3 (after fixture)
```

**Success = the daemon returns `Submitted` (pool) and confirms (block-accept) for
a wallet-built transfer over depth-2 and depth-3+ trees, the two reanchor cases
re-accept, and the 5 `recon_tier_b.rs` tests pass against `ct2_tier_b.json`.**
