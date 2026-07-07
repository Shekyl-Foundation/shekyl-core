# Track-2 North Star — first daemon-accepted FCMP++ spend (SAL frontier)

**Status:** Open — one localized fix from green. **Branch:** `feat/track2-northstar`
(off `dev`, commit `23f853051`). **Parent:** [`TRACK2_REGTEST_PARITY.md`](TRACK2_REGTEST_PARITY.md).
This is the executable brief for the remaining step; it can be handed to a fresh
context. Read the "Bootstrap" section first.

---

## 1. Objective

Make `e2e_fcmp_spend_accepted_by_daemon` (the Track-2 north-star gate, in
`rust/shekyl-engine-core/src/engine/regtest_e2e.rs`) pass: a real FCMP++ spend,
built by the production `Engine` from a refresh-scanned output, **submitted to a
live `shekyld` and accepted by its consensus verify**. This is the first-ever
daemon-accepted FCMP++ spend; it proves wallet↔daemon submit/verify parity and
unblocks **CT-2 Tier-B** and **CT-5 depth-3+** validation.

## 2. State — done, do not redo

Driving the north-star against a live daemon already proved + fixed, in order:

1. **Refresh/scan works live.** The wallet scans coinbase and reports a spendable
   balance (~13.9T au) against the daemon — coinbase wire parse (`shekyl-wire`),
   ownership scan, curve-tree ingest, maturity all proven end-to-end. The original
   Track-2 block is cleared.
2. **Async send API (committed).** `Engine::build_pending_tx`/`submit_pending_tx`
   are sync wrappers that poll the `PendingTxEngine` future once and bail on
   `Pending`, but production `LocalPendingTx::build` is async (awaits the
   curve-tree actor's `AssembleTx` to assemble the membership path) and `submit`
   awaits the daemon RPC. Added `Engine::build_pending_tx_async` /
   `submit_pending_tx_async` (`pending.rs`) — the "async `Engine` methods" the sync
   wrapper's own doc anticipates; needed by any real CLI/RPC caller.
3. **Reference-spendability retry (committed).** The spend selects against the
   *reference* block (tip − `REF_ANCHOR_AGE`), which matures a few blocks after the
   tip; the funding loop stopped at tip-maturity and hit a correct
   `OutputNotYetSpendable`. The build now retries, mining until the C2 gate clears.

## 3. The frontier — the single remaining fix

The build now reaches the FCMP++ **SAL prover** and fails:

```
FcmpProveError("upstream proof generation failed: OpenedInputTuple::open failed at input 0")
```

`OpenedInputTuple::open` (`rust/shekyl-oxide/.../shekyl-fcmp-proofs/src/sal/mod.rs:243-256`)
returns `None` when

```
(Ed25519::generator() * x) + (EdwardsPoint(*T) * y_tilde) != rerandomized_output.input.O_tilde
```

— i.e. the **output-key opening `O = x·G + y·T` fails**. The witness `x`/`y` come
from `bundle.spend_key_x`/`bundle.spend_key_y` (`shekyl-engine-core/src/engine/
sign_bridge.rs:137-138`), derived by the **KeyEngine**. The commitment/mask are
already correct (the build passed the leaf-chunk `(O, C)` lookup at
`signing_assembly.rs:164` before reaching `open`), so the failure is specifically
the `(x, y)` spend-key derivation.

**Why it surfaces now:** every prior test — including the in-process oracle
`rust/shekyl-wire/tests/fcmp_spend_e2e.rs`
(`fcmp_spend_real_tree_verifies_against_consensus`, green) — uses *synthetic*
`(x, y)` satisfying `O = xG + yT` by construction. This is the **first time real
scanner-derived spend keys feed the SAL prover.** The bug is wallet-side key
derivation for a scanned (coinbase) output — **not** the daemon, the wire
(`shekyl-wire`, canonical), or the verifier (shared FFI).

## 4. Where to fix it

The KeyEngine's per-output spend-key derivation that fills
`bundle.spend_key_x`/`spend_key_y`. Resolve at source: Shekyl uses two-component
output keys (`O = xG + yT`; `shekyl-fcmp/src/proof.rs:164-165`: "legacy one-time →
`y=0`; two-component → non-trivial `y`"). Determine whether the scanned coinbase
output's `O` carries a non-zero `T`-component, whether the KeyEngine derives both
`x` and `y` correctly for it, and whether coinbase derivation differs from a
regular output's. Trace: scanner output detection → KeyEngine bundle derivation →
`sign_bridge.rs:137`.

## 5. Diagnosis recipe (fastest path)

1. Add a temporary `eprintln!` in `sign_bridge.rs` (or the KeyEngine) dumping, for
   input 0: `spend_key_x`, `spend_key_y`, the output key `O` (`output_key`), and
   whether `x·G + y·T == O` recomputed. (There is a "no debug macros in production"
   CI lint — revert before committing.)
2. Compare against `fcmp_spend_e2e.rs`'s synthetic witness (which opens correctly)
   to see which of `x`, `y`, or the `O` mapping diverges.
3. Fix the derivation; re-run; expect `build` to succeed, then
   `submit_pending_tx_async` → the daemon's mempool verify accepts (`Ok`), then the
   block-accept confirm.

## 6. How to run

```bash
cd /abs/worktree/rust
SHEKYLD_BIN=/abs/build/bin/shekyld \
  cargo test -p shekyl-engine-core --lib e2e_fcmp_spend_accepted_by_daemon -- --ignored --nocapture
```

- `build/bin/shekyld` (dated 2026-06-24, dev-current, has `GET_CURVE_TREE_PATH`
  post-#174) is usable as-is; rebuild from dev only if a daemon-side issue appears.
- The run takes ~3–4 min (mines ~70–90 blocks in batches + refreshes) — **run it
  in the background** (it exceeds a 2-min foreground cap) and read the output file.
- The shared `rust/target` is used by other in-progress work — **do not
  `cargo clean` it**; check for active builds before any daemon rebuild.

## 7. After it goes green

1. The accepted spend is the live submit/verify-parity proof. Keep the test
   `#[ignore]`d (it is the live gate; CI provides no daemon).
2. Unblocks **CT-2 Tier-B** (generate `ct2_tier_b.json` from the now-working
   regtest spend path; un-ignore `recon_tier_b.rs`'s 5 tests) and **CT-5 depth-3+**.
3. Consider promoting `build_pending_tx_async`/`submit_pending_tx_async` to a
   reviewed PR (the general async send API any CLI/RPC caller needs).
4. Gates before commit: `cargo fmt` + `cargo clippy -p shekyl-engine-core
   --all-targets -- -D warnings`; commit on `feat/track2-northstar`; push is
   separately authorized (rule 06).

## 8. Constraints / framing

The crypto and wire are **shared/canonical** — the daemon verify is the same Rust
`shekyl_fcmp::proof::verify` via FFI; the spend layout is `shekyl-wire` (PR #178).
The remaining bug is **wallet-side key derivation** — Rust, our code; fix it
Rust-side (rules 20/36, Rust owns secrets). Honor rules 30 (crypto discipline),
36 (secret locality), 45 (fmt/clippy), 50 (testing), 06 (branching). The KeyEngine
derivation is consensus-adjacent crypto — verify against the SAL relation, do not
guess.

## 9. Bootstrap (read first)

- Memory `track2-regtest-blockwire` (full Track-2 state + this frontier with
  file:line), `consensus-port-gates-genesis`, `fcmp-spend-rpc-bug`.
- In-process oracle for a correct spend witness:
  `rust/shekyl-wire/tests/fcmp_spend_e2e.rs`.
- SAL: `shekyl-fcmp-proofs/src/sal/mod.rs`. Witness assembly:
  `shekyl-engine-core/src/engine/{sign_bridge.rs,signing_assembly.rs}`. Test:
  `regtest_e2e.rs::e2e_fcmp_spend_accepted_by_daemon`.
- Commit `23f853051` on `feat/track2-northstar` (async-API + retry fixes; its
  message documents this frontier).

## 10. Start here

Re-run the north-star (§6), confirm it still fails at `OpenedInputTuple::open at
input 0`, add the `(x, y, O)` dump for input 0, find which scanner-derived
spend-key component fails `O = xG + yT`, fix the KeyEngine derivation, and drive it
to a daemon-accepted spend.
