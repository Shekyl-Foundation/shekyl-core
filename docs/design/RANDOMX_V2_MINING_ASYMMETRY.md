# RandomX v2 — mining floor-vs-ceiling asymmetry investigation (pre-genesis-seal security disposition)

## Front-matter

| Field | Value |
|-------|-------|
| Status | **Measurement design — Phase 0 COMPLETE; Phases 1–3 not yet executed.** No timing number is a result until Appendix B is filled from a source-verified run. **Phase 0 is fully discharged (2026-07-06):** the constant diff shows no delta (§3.1) and the runtime byte-equality differential passes **1024/1024** — stock XMRig 6.26.0 `rx/2` full-dataset is byte-identical to Shekyl's canonical (§3.2), so the ceiling miner is **stock XMRig, no patch** (§3.3). Key nuance: XMRig's *light/verification* path is v2-incomplete; the ceiling must use its full-dataset (mining) mode. Artifact: [`tests/randomx_v2_parity/xmrig_ceiling/`](../../tests/randomx_v2_parity/xmrig_ceiling/). Revised after **red-team rounds 1–2** (§11 — F1–F7 structural: four-factor decomposition, aggregate-H/s basis, whale-produces-Shekyl-blocks gap, threshold arithmetic, two-ended range; R1–R4 polish: decomposition-is-an-aid-not-identity, hash-core-vs-block-framing layer split, §6.4-pinned prototype greenlight, confirmed-huge-page provenance; Intel-first / Ryzen-rig two-machine plan). |
| Kind | Security investigation (consensus 51%-via-asymmetry, genesis shallow-work window). **Not** a performance-tuning exercise. |
| Priority order | privacy > security > correctness > performance > features. This study lives at the security tier; the numbers it produces feed a consensus-security decision. "Get-it-right, not get-it-now" ([`00-mission`](../../.cursor/rules/00-mission.mdc), [`05-system-thinking`](../../.cursor/rules/05-system-thinking.mdc)). |
| Parent plan | [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) (Track B); [`RANDOMX_V2_PHASE3_PLAN.md`](./RANDOMX_V2_PHASE3_PLAN.md) (§7 Hole-1 gate, §9 test-gates table — the CI regime this study extends). |
| Spec authority | [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) §6 (no-prewarm / no-dataset decision — the thing disposition option (a) would revisit), §13 (non-goals). This doc **cites**; it does not re-derive. |
| Sibling (harness) | [`RANDOMX_V2_PHASE2G_PLAN.md`](../completed/RANDOMX_V2_PHASE2G_PLAN.md) (the differential harness — **light-vs-light only**; the C-full and XMRig legs this study needs do not exist there). |
| Base commit | `d05d64666` (`dev` tip at survey time; all line numbers in Appendix A are against this commit). |
| Fork pin | `external/randomx-v2` at `aaafe71` (v2.0.1). Coupled to `randomx-v2-sys` via `fork-pin-sha` ([`rust/randomx-v2-sys/Cargo.toml:48-49`](../../rust/randomx-v2-sys/Cargo.toml)). |
| Working branch (doc) | `docs/randomx-mining-asymmetry` (off `dev`; design docs land on `dev` per branch policy). |
| Working branch (code) | The bench legs, XMRig integration, whale harness, and any Rust-full prototype get **their own** branch off `dev` — this doc does not carry code. |
| Reopen clause | §10 — "accept the gap" is itself a security choice with a threat model; recorded with a [`21-reversion-clause-discipline`](../../.cursor/rules/21-reversion-clause-discipline.mdc) reopen criterion, not left implicit. |

---

## 0. What this investigation is, and what governs it

The genesis mining asymmetry is the ratio **ceiling ÷ floor**:

- **floor** = the hashrate an honest participant achieves with *what Shekyl ships* — today, the pure-Rust software verifier/miner path (`shekyl-pow-randomx`, light-mode, JIT-off, no dataset).
- **ceiling** = the hashrate an adversary achieves with the *best available tooling* — a fully tuned miner (XMRig on the RandomX-v2 algorithm) and, as a documented tail, a RandomX ASIC.

That ratio is the multiplier by which an attacker undercuts the visible network's hardware to reach 51%, during the shallowest-work window of the chain's life. The deliverable is the **evidence base** for a pre-genesis-seal decision across three options — (a) first-party Rust dataset/full-memory mode to raise the floor; (b) bless a reference XMRig to raise the floor; (c) accept the gap with a documented difficulty/checkpoint posture. **This investigation does not make that decision. It produces the numbers and the live-network behavior.**

### 0.1 Standing rules in force (non-negotiable, apply to every phase)

1. **Verify at source, not from memory.** Every claim about what a component does, what mode it runs in, or what a number represents is established by call-graph / flag-inspection / config trace at `file:line` in the *live* repos — never from doc comments, changelog lines, agent reports, or prior statements. All three have been wrong in this program before, and **one already lied in the grounding for this very document** (§1.4).
2. **No number without provenance** (§2). Hardware, build, mode, corpus — recorded or the number is void.
3. **Wargame the optimistic-error direction.** For every measurement, ask what would make the asymmetry look *smaller* than reality — because that is the only error direction that gets someone hurt (a chain shipped believing it is safe when it is not). Each phase below has an explicit "optimistic-error guard."
4. **Never rerun-until-green.** A surprising number gets its cause identified, not averaged away. A measurement that can't be trusted is worse than none — it produces false confidence in a consensus-security decision.

---

## 1. Premise reconciliation — what the source grounding changed before any measurement

The investigation brief carried several assumptions that source verification corrected. Recording them here so the plan is built on the tree as it is, not as the brief imagined it.

### 1.1 There is no F-series / T-series test tracker in the index
The brief refers to "F4b / F4c / F6 / F7" and "T5 / T7 / T8" as if `docs/design/IMPLEMENTATION_INDEX.md` enumerates them. It does not. The **F-series are doc-scoped design findings** (Phase 2C §5, Phase 2F §4); the **T-series are test IDs** living in `RANDOMX_V2_PHASE2C_PLAN.md` §6 and the `RANDOMX_V2_PHASE3_PLAN.md` §9 gates table. This study's tracking lives in *this doc* and the Phase 3 gates table, not the index. (Per [`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc), if this study spawns a new identifier family — e.g. an `MA-N` mining-asymmetry test series — it registers in the index at birth.)

### 1.2 `LATENCY_RATIO_BUDGET.md` does not exist yet — this study creates it
`RANDOMX_V2_PHASE3_PLAN.md:548` (the T5 gate row) points its "canonical record" at `LATENCY_RATIO_BUDGET` — a **dangling forward-reference**; no such file exists. The committed figures live only inline in that row: **1.817× on the committed runner class** against a **≤3.0× budget** ("budget holds, ~39% headroom"), with **dev-hardware ~3.1× readings flagged as a hardware artifact** (no drift vs the 2g-close pin). Phase 1's language-factor cross-check (§4) is the natural moment to *create* `docs/design/LATENCY_RATIO_BUDGET.md` and close that dangling reference.

### 1.3 The existing "three-leg" is **not** the differential this study needs
Today's three-leg differential is **rust-light ≡ C-light ≡ canonical-pin** (`mode_correctness.rs:272`; corpus `corpus_random.rs`). It is *light-vs-light*. The brief's target — **XMRig-produced hash ≡ C-full ≡ Rust-light** — bridges two things the codebase keeps *separate*:
- The **C-full / miner-produced** leg is the distinct **Hole-1 gate** (`RANDOMX_V2_PHASE3_PLAN.md:436` §7), with a miner KAT already pinned at `tests/randomx_v2_parity/randomx_v2_miner_kat.cpp` (`randomx_v2_full_parity_miner_kat`, status *discharged*).
- **No XMRig leg exists anywhere.** `grep xmrig` across `shekyl-randomx-differential` returns nothing.

So the "shared-corpus equivalence that licenses a ceiling number" is **new ground**. Phase 0 builds it by *reusing* the Hole-1 C-full path and *adding* an XMRig leg, without touching the equivalence-critical oracle.

### 1.4 A grounding leg reported anchors from an absent clone — caught, then re-verified
The first recon leg reported precise `file:line` anchors from `/home/torvaldsl/shekyl/xmrig` ("`src/version.h:14` → 6.26.0", "`RxAlgo.cpp:35-36` → `RX_V2`") **while that directory did not exist on disk** (verified: `ls -ld` → *No such file or directory*). Those anchors came from the model's knowledge of XMRig's public source, **not** from a local clone — precisely the memory-not-source failure rule 0.1 forbids for a security claim. This is recorded, not scrubbed, as a live instance of why the rule exists.

The clone was subsequently created (`b2ca7248 v6.26.0`) and the claim **re-verified at source in the local tree**: the `RX_V2` path (`src/crypto/rx/RxAlgo.cpp:35-36` → `RandomX_MoneroConfigV2`) selects `ProgramSize = 384` with the four v2 tweaks (`src/crypto/randomx/randomx.cpp:57-62`), and every Argon/cache/dataset/scratchpad/jump/program constant is byte-identical to `external/randomx-v2/src/configuration.h` (§3.1 table). So the conclusion "**stock XMRig 6.26.0 on `rx/2` needs no constant-level patch**" is now a **source-verified finding at the constant level** — but constant identity is *necessary, not sufficient* for byte-identical hashes. Two distinct things must still agree at runtime, **at two different layers** (R2 — do not blur them): (1) the **hash core** — the tweak code paths, proven at the **raw-blob layer** by the §3.2 differential (XMRig's `randomx_calculate_hash` / benchmark hash-dump fed the same bytes the C oracle gets); (2) the **block-hashing-blob framing** — how a Shekyl block serializes into the bytes that get hashed, a strictly larger question proven separately at the **block layer** (§6.3). The §3.2 hash-core proof licenses the **ceiling number**; the §6.3 framing work licenses the **whale**.

### 1.5 The C-full and JIT bench legs require **new, bench-only** FFI — deliberately kept out of the oracle
`randomx-v2-sys` binds exactly 7 light-mode symbols and **deliberately does not declare the dataset/JIT surface** (`rust/randomx-v2-sys/src/lib.rs:75-80`: "The harness is light-mode-only; dataset-related symbols are not declared here on purpose"). The C oracle allocs with `RANDOMX_FLAG_DEFAULT` and creates the VM with `RANDOMX_FLAG_V2` + NULL dataset (`c_oracle.rs:290,305`) — JIT off, full-mem off, large-pages off. Measuring **C-full** and **C-full+JIT** (§4) therefore requires binding `randomx_alloc_dataset` / `randomx_init_dataset` / `randomx_vm_set_cache` and the `RANDOMX_FLAG_FULL_MEM|JIT|LARGE_PAGES` flags in a **separate bench-only surface** that the oracle never links — see §4.3.

---

## 2. Provenance protocol (mandatory per number)

No H/s, ratio, or watt figure is admissible without **all** of the following recorded alongside it in Appendix B:

| Axis | Fields |
|------|--------|
| **Hardware** | CPU model + microarch, physical cores / SMT threads, RAM type + speed, huge-pages state (2 MiB / 1 GiB, count, applied?), MSR tweaks applied? |
| **Build** | compiler + version, opt flags, LTO on/off, `target-cpu` (e.g. `native` vs a pinned baseline), `RANDOMX_V2_INSTALL_DIR` provenance for the C leg |
| **Mode** | light / full; JIT on/off; dataset present?; **thread count (first-class — the ratio moves with it, §4.3)**; **memory-subsystem tuning: 1 GiB huge-pages — reservation *confirmed successful, not merely requested* (the miner logs the page size actually used; a silent 1 GiB→2 MiB fallback measures a lower tuning factor = an optimistic error, R4); MSR / prefetcher writes applied?** (a privileged fourth factor, §4.2); `RANDOMX_FLAG_V2` set? (program size 384 vs 256 — a wrong-algo run is a wrong-hash run) |
| **Corpus** | seedhash set + count, data blob count, the exact corpus generator + seed (`corpus_random.rs` `RANDOM_CORPUS_SEED_V1_SOURCE` or a named alternative) |
| **Interpretation** | what one number *is*, and the arithmetic. **The mining-asymmetry ratio is full-machine aggregate H/s ÷ full-machine aggregate H/s** — never single-thread-inverted (that is best-case, contention-free; §4.3). Single-thread per-hash latency is retained *only* for the T5 **verification**-latency budget (verifying one block is single-threaded — a different question), never as the mining-ratio basis. |

**Hardware caveat, load-bearing.** The dev box (`i9-11950H`, 8c/16t, 125 GiB RAM) is a valid site for **hardware-independent** counts and for *reproducing a ratio's shape*, but **ratios are hardware-dependent**: the T5 language factor reads ~1.817× on the committed CI runner class and ~3.1× on this dev box — same code, different silicon. **Never judge a runner/network budget from a dev-box ratio.** Every ratio in this study is reported *with the silicon it was measured on*, and the disposition is made against the runner-class (or pessimistic-tail) number, not the dev-box number. One tuning-factor caveat compounds this in the *optimistic* direction: the MSR / prefetcher gains XMRig exploits are largely **AMD Ryzen**-specific, so the memory-tuning factor (§4.2) measured on the Intel dev box **understates** what an attacker on Ryzen silicon achieves. That must be flagged on the number, not silently absorbed — the true ceiling's tuning multiplier is a Ryzen measurement we do not have on this box.

**Two-machine plan (the caveat has a discharge path, it is not a permanent hedge).** Phase 1 runs first on the **Intel dev box** (`i9-11950H`) — valid for the language/dataset/JIT factors and for standing the harness up — while an **attacker-representative Ryzen rig (`9950X3D`)** is built. When the rig is ready, the tuning factor and the ceiling are **re-measured on Ryzen** (where the MSR/prefetcher levers actually land), and that Ryzen number — not the Intel one — feeds the disposition. Until then the §4.2 tuning factor is explicitly labeled a **floor on the factor, pending Ryzen** (magnitude unknown, direction known). Running both is also a deliberate **comparison surface**: the Intel↔Ryzen spread on the tuning factor is itself a datum about how hardware-dependent the ceiling is.

---

## 3. Phase 0 — establish the fork delta (gates everything downstream)

**Purpose:** decide the ceiling artifact — is the ceiling miner "stock XMRig 6.26.0 on `rx/2`," "XMRig + small patch," or "XMRig + core fork"? A ceiling number from a miner that computes a *different* hash than Shekyl validates is not a ceiling — it is noise wearing a security label.

### 3.0 Prerequisite: pin the XMRig clone (DONE)
Per §1.4 the clone was initially absent; it now exists at `/home/torvaldsl/shekyl/xmrig`, HEAD **`b2ca7248 v6.26.0`** (`src/version.h:14` → `APP_VERSION "6.26.0"`; RandomX source under `src/crypto/randomx/`). Treat it like the Tor Expert Bundle pin — a hash-pinned external artifact with a release-watch duty; record the SHA in Appendix A and re-pin deliberately on any bump. **Before any measurement, `git checkout b2ca7248` in the clone and confirm HEAD matches this pin.** A `git pull` is *watching upstream*, not adopting it; re-pinning is a deliberate act that **invalidates every prior ceiling number until it is re-run** (the ceiling is only meaningful against a fixed miner). Keep the clone; pin the checkout.

### 3.1 The constant diff (DONE — no delta)
Diffed Shekyl's fork (`external/randomx-v2` @ `aaafe71`, verified pristine tevador v2.0.1 — working tree clean, no `shekyl` markers in `src/`) against XMRig 6.26.0's `RX_V2` config, **at source in both local trees**. XMRig selects the v2 config at `src/crypto/rx/RxAlgo.cpp:35-36` (`RX_V2 → &RandomX_MoneroConfigV2`); the preset (`src/crypto/randomx/randomx.cpp:55-62`) overrides only `ProgramSize = 384` and the four tweaks, inheriting the base defaults (`randomx.cpp:124-133`, `randomx.h:70-76`). Every constant matches:

| Constant | XMRig `RX_V2` | Shekyl fork | |
|---|---|---|---|
| Argon memory / iter / lanes / salt | 262144 / 3 / 1 / `RandomX\x03` (`randomx.h:70`, `randomx.cpp:124-126`) | 262144 / 3 / 1 / `RandomX\x03` (`configuration.h:32,35,38,41`) | ✓ |
| Cache accesses / superscalar latency | 8 / 170 (`randomx.h:71`, `randomx.cpp:127`) | 8 / 170 (`:44,47`) | ✓ |
| Dataset base / extra | 2147483648 / 33554368 (`randomx.h:73-74`) | 2147483648 / 33554368 (`:50,53`) | ✓ |
| **Program size (v2)** / iterations / count | **384** / 2048 / 8 (`randomx.cpp:57,132-133`) | **384** / 2048 / 8 (`:57,62,65`) | ✓ |
| Scratchpad L3 / L2 / L1 | 2097152 / 262144 / 16384 (`randomx.cpp:130,129,128`) | same (`:68,71,74`) | ✓ |
| Jump bits / offset | 8 / 8 (`randomx.h:75-76`) | 8 / 8 (`:77,80`) | ✓ |
| v2 tweaks (CFROUND/AES/PREFETCH/COMMITMENT) | all = 1 (`randomx.cpp:59-62`) | active under `FLAG_V2` (`program.hpp:57`) | ✓ |

**No constant differs.** No constant-level patch to XMRig is required; the ceiling-artifact candidate is **stock XMRig 6.26.0 launched on algorithm `rx/2` (`RX_V2`)**. (The local `/home/torvaldsl/shekyl/RandomX` clone, HEAD `0720fe4d`, two dev-tooling commits atop `aaafe71`, has `configuration.h` byte-identical to the fork — a convenient cross-reference, but cite the fork, not it.)

### 3.2 The remaining Phase 0 task — hash-core byte-equality differential at the raw-blob layer (DONE — 1024/1024 byte-identical)
Constant identity is **necessary, not sufficient**. What licenses a **ceiling number** is a runtime proof at the **hash-core / raw-blob layer**: XMRig's `randomx_calculate_hash` for a given `(seedhash, blob)` is **byte-identical** to Shekyl's canonical pins **fed the same raw bytes**. This is the layer *below* block framing — it proves the four v2 tweak code paths agree, which is exactly what a ceiling number needs and **all** it needs.

**Result (2026-07-06):** a harness linking **XMRig 6.26.0's actual RandomX sources** (`b2ca7248`) against a minimal honest support layer, run over the pinned 1024-vector corpus, gives **1024 / 1024 byte-identical, 0 mismatches** — provided XMRig hashes in **full-dataset (mining) mode**. Artifact + reproduction: [`tests/randomx_v2_parity/xmrig_ceiling/`](../../tests/randomx_v2_parity/xmrig_ceiling/). Build proven faithful by reproducing the published rx/0 v1 reference vector (`639183aa…`) exactly. Software AES throughout — matching the fork's soft-AES `c_oracle` canonical (RandomX mandates soft==hard output, so this is apples-to-apples).

- **The mode is load-bearing (a refinement of R2).** XMRig's **light / verification** path is v2-**incomplete**: its interpreter applies only `Tweak_V2_PREFETCH` (`vm_interpreted.cpp:82`); the other three tweaks (`AES`/`CFROUND`/`COMMITMENT`) exist only in its JIT, and even its light-JIT diverges from its own full-dataset result (`2fe105f9…` vs the canonical `34f8b017…`). So XMRig's own mode-invariance is broken **in the verification path miners never use**. The ceiling comparison therefore must use XMRig's **full-dataset** hash — which is exactly the mode an adversary mines with. This is the precise trap the "necessary, not sufficient" stance warned about: §3.1's constants all matched, yet testing XMRig's *light* path would have produced a **false divergence**.
- **Corpus (R2):** the existing raw-blob corpus (`corpus_random.rs`, 32×32) reaches the harness via `parity_corpus.dat` (SHA-256 `713d5702…`, carrying the committed `CANONICAL_RANDOM_HASHES`). Not conflated with the block-layer equivalence (§6.3 shim), which remains a separate deliverable.
- **On divergence** — none at the hash core. (The light-vs-full divergence is intra-XMRig, not XMRig-vs-Shekyl, and does not touch the ceiling.)

### 3.3 Ceiling-artifact decision — SETTLED: stock XMRig 6.26.0 on `rx/2`, no patch
Both legs are discharged: the constant diff (§3.1) shows no constant-level patch is needed, and the runtime differential (§3.2) shows XMRig's full-dataset `rx/2` hash is byte-identical to Shekyl's canonical across all 1024 vectors. **The ceiling miner is stock XMRig 6.26.0 launched on algorithm `rx/2`, full-dataset mode — no patch, no fork.** The correctness of every subsequent ceiling H/s number rests on this proof, which was established *before* any timing was taken. (The Phase-1 XMRig point must run full-dataset for the same reason; its light path computes a different, v2-incomplete hash.)

**Optimistic-error guard (Phase 0):** the dangerous misconfiguration is XMRig left on the **wrong algorithm** (`rx/0` = program size 256, no v2 tweaks). That path is *faster* (smaller program) but computes a *wrong* hash — if mistaken for the ceiling it would *inflate* the ceiling, which is the pessimistic direction and thus self-flagging. The subtler danger is the reverse: a *correct* XMRig that we fail to feed the v2 flag on the **Shekyl** side — confirm `shekyl-pow-randomx` / the C oracle actually run `RANDOMX_FLAG_V2` (value 128) so both sides are on the 384/tweaked path. Mismatched algo → the differential fails loudly, which is the design working.

**Gate:** ~~do not proceed to Phase 1's ceiling leg or Phase 3's whale until §3.0–§3.3 are answered and the XMRig leg passes the differential.~~ **CLEARED (2026-07-06):** §3.0–§3.3 answered, XMRig full-dataset leg passes 1024/1024. Phase 1's ceiling leg and Phase 3's whale are unblocked (both must use XMRig full-dataset).

---

## 4. Phase 1 — the factorial (controlled harness, single fixed machine)

**Purpose:** isolate the **four** gap factors (dataset, JIT, memory-tuning, language — *not fully independent*; see the R1 caveat in §4.2) on one machine, same corpus, same seedhash set, so the disposition can cost each lever separately — never as one lumped "Rust is slower."

### 4.1 Required measurement points

| Point | Mode | Where it comes from |
|-------|------|---------------------|
| **C-light** | JIT-off, no dataset (interpreter) | the existing `c_oracle` path (`c_oracle.rs:281-317`) |
| **C-full / no-JIT** | FULL_MEM dataset, interpreter | **new** bench-only FFI (§4.3) |
| **C-full + JIT** | FULL_MEM dataset, JIT | **new** bench-only FFI (§4.3) — the reference fast path |
| **Rust-light** | shipped verifier/miner | `shekyl-pow-randomx::compute_hash` (`lib.rs:196`, `vm.rs`) — inherently light/JIT-off; computes dataset items on the fly (`vm.rs:355-357`) |
| **XMRig** | patched-per-Phase-0, tuned (huge-pages + MSR + optimal threads) | the real adversary config |
| *(Rust-full)* | *if prototyped* | §9 — only if the dataset factor says it's worth building |

### 4.2 The **four** decomposed factors (report separately, never lumped)
The brief named three; source-grounding a fourth is mandatory, because it is the one that mis-costs option (a).
- **Dataset factor** = C-full ÷ C-light (same language, **tuning held equal — huge-pages/MSR off on both**). What materializing the 2 GiB dataset buys.
- **JIT factor** = (C-full+JIT) ÷ C-full (same language, tuning equal). What the x86-64 codegen buys.
- **Memory-tuning factor** = (C-full+JIT, huge-pages + MSR **on**) ÷ (C-full+JIT, tuning **off**). Isolated by toggling `LARGE_PAGES` (and the MSR writes where the silicon supports them). This is a **privileged memory-subsystem lever** (1 GiB pages, prefetcher/cache-QoS MSRs) that RandomX is specifically designed to reward — a **separate lever** from JIT and language, though it **interacts with the dataset factor** (huge pages help *because* of the 2 GiB dataset — see the R1 caveat below), and **unreachable by a `#![deny(unsafe_code)]` Rust verifier without an architectural change**. Measuring it is what stops the ceiling-vs-floor gap from silently folding a tuning multiplier into "dataset × JIT." (Hardware-dependent and Ryzen-favouring — see the §2 caveat; the dev-box Intel number is a floor on this factor.)
- **Language factor** = Rust-light ÷ C-light (same mode, tuning off on both). **This is the ~1.817×-runner / ~3.1×-dev-box T5 number** — confirm it *reproduces* here as a harness cross-check (a divergence means the harness is wrong, not the language).

**Decomposition is an aid, not an identity (R1).** The four factors are **not** cleanly orthogonal: the memory-tuning factor and the dataset factor *interact* — 1 GiB huge-pages help precisely because the randomly-accessed 2 GiB **dataset** is what thrashes the TLB, and do far less for light mode (the 256 MiB scratchpad already fits comfortably in fewer entries). So the tuning multiplier measured on C-full is not the multiplier you'd see on C-light, and `dataset × JIT × tuning × language` will **approximate, not equal**, the directly-measured endpoints. Therefore: **measure the total gap directly** — Rust-light-floor ÷ XMRig-ceiling — as the ground truth, and treat the four factors as the *explanatory breakdown* that should approximately reconstruct it. A large residual between the product and the direct total is **itself a finding** (an unmodeled interaction, or a measurement error) — and a built-in cross-check on the whole factorial.

**Lever identification (why decompose):** applying the *dataset factor* to *Rust-light* predicts what a Rust dataset mode (option a) would buy **without building it** — the trigger for §9. But the prediction is an **upper bound**, not the floor it would deliver: Rust-full inherits the dataset factor and **not** the memory-tuning factor (privileged, unsafe). §9 and the option-(a) disposition (§10) both carry that caveat explicitly.

### 4.3 Harness construction — do NOT contaminate the oracle
The equivalence-critical differential oracle **stays JIT-off light-mode for determinism**. Contaminating it with JIT/dataset would trade a consensus gate for a benchmark. Therefore:
- Build the timing path as a **separate bench mode / separate bench-only sys surface**. The dataset+JIT symbols (`randomx_alloc_dataset`, `randomx_init_dataset`, `randomx_vm_set_cache`, flags `FULL_MEM|JIT|LARGE_PAGES`) are bound **only** in this bench crate, never in `randomx-v2-sys`'s oracle surface (which stays the 7 light-mode symbols, per §1.5). The `nm` isolation contract (`scripts/ci/check_randomx_symbol_isolation.sh`) still guarantees none of this reaches `shekyld`.
- **Aggregate, not single-thread, is the ratio basis.** RandomX is cache/bandwidth-bound, so per-thread H/s *degrades* as threads contend for shared L3 and memory bandwidth. An honest miner and an attacker each extract **full-machine aggregate** from one box — that is the like-for-like quantity, so both floor and ceiling are reported as full-machine aggregate H/s at the deployment thread count, with single-thread as a secondary datum (and reserved for the T5 verification budget, §2). Single-thread-inverted H/s is contention-free best-case and would understate the *floor*'s aggregate less than the *ceiling*'s (the tuned miner saturates bandwidth harder) — an optimistic-error direction. Thread count is therefore a first-class provenance axis (§2), and the **dataset factor is a curve over thread count, not a scalar**: at one thread the dataset's no-recompute win is large and bandwidth uncontended; at N threads saturating bandwidth it erodes while light-mode's per-item compute stays parallel. Measure it at the deployment thread config; the Rust-full prediction (§9) carries the bandwidth-contention caveat.
- **Interleave only the footprint-matched language factor.** `mode_latency.rs`'s interleaved same-process discipline cancels runner noise *when both legs have matched footprints* (light C ~256 MiB vs light Rust ~256 MiB). Interleaving a **full-dataset C VM (2 GiB resident) against a light Rust VM (256 MiB)** makes each leg's measurement run while the other's footprint evicts its cache and contends for bandwidth — the interleave that cancels noise now *creates* cross-contamination. So: interleave for the **language factor** only; measure the **mode factors (dataset / JIT / tuning) sequentially**, with the other VM torn down and its memory released before timing, accepting more runner noise in exchange for footprint isolation.
- Report absolute H/s from a dedicated throughput bench; the criterion benches at `shekyl-pow-randomx/benches/` currently measure the Rust leg's single-thread per-hash latency (invert for single-thread H/s — the secondary datum), so a **new aggregate/multi-thread throughput bench** is needed for the ratio basis.

### 4.4 Efficiency axes (two, kept distinct)
Report alongside raw **H/s**, as **two separate axes** — they answer different halves of the attack-cost question and age differently:
- **H/watt** — sustained-attack cost; physically stable (silicon efficiency doesn't drift with markets). This is the CPU-egalitarian / running-cost axis.
- **H/$** — acquisition cost; **market-drifting** (hardware prices move), so it is timestamped and treated as a snapshot, not a constant.

Lumping them under one "efficiency" number would blend a stable physical quantity with a volatile market one — an ASIC's H/s and its H/watt tell different halves of the 51%-cost story, and its H/$ is a third thing that is stale the moment it is written.

**Optimistic-error guard (Phase 1):** the asymmetry looks *smaller* if the **floor is measured too high** or the **ceiling too low**. Guards: (1) measure Rust-light in its *shipped* configuration, not a bench-tuned build with `target-cpu=native` the honest user won't have; (2) measure C-full+JIT and XMRig *fully tuned* (huge-pages + MSR + optimal threads) — an untuned ceiling understates the adversary; (3) record every axis of §2 so a too-flattering number can be traced to a config difference rather than averaged away.

---

## 5. Phase 2 — anchor the ceiling *and floor* ranges against reality; name what the harness can't see

The Phase-1 XMRig number is the **software ceiling on your silicon**. The *true* ceiling is higher in two ways that must be stated, never zeroed:

1. **Tuned-miner headroom.** Record what a known-good XMRig config achieves on the same silicon; flag any gap beyond your build as **"unmeasured optimization headroom,"** never as zero. (Compounded by the Ryzen-favouring tuning factor of §2/§4.2: the dev-box Intel ceiling understates a Ryzen attacker.)
2. **The ASIC leg — reframed from "will an X9 boot" to "is the threat class live."** The decision-relevant question is *not* whether a specific Antminer X5 (~212 kH/s) / X9 (~1 MH/s) / Pinecone R1X (~1.2 MH/s) — ecosystem/vendor claims, **not benchmarked here** (we have no such hardware) — is field-reparameterizable across the 256→384 program-size change; that is genuinely uncertain and firmware-dependent (RandomX ASICs are *necessarily* semi-general VM executors, so it *may or may not* be absorbed — hedge, do not assert). The **certain** fact is that the ecosystem has demonstrably fabbed RandomX silicon, so the **capability to target Shekyl-v2 with modest NRE unambiguously exists**. The pessimistic disposition rests on **"the ASIC design-capability threat class is live"** (certain) rather than **"an existing X9 repurposes today"** (uncertain) — which makes the tail firm without over-claiming about any specific unit.

### 5.1 The floor is a range too
Symmetric with the ceiling, the floor is not a point. It spans a **portable release binary** (conservative `target-cpu`, what most honest users actually run) at the low end, to a **from-source `target-cpu=native` build** (what a competent hobbyist runs) at the high end. The §4.4 guard's "measure Rust-light in shipped config, not native" is measuring **floor-low**, which is correct — but the plan states explicitly that the **pessimistic asymmetry pairs floor-low (portable release) ÷ ceiling-high (ASIC-tail)**, treating the floor's spread with the same rigor as the ceiling's rather than collapsing it to the native-build best case.

**Output:** the asymmetry stated as a **range across both ends** — ceiling-high (ASIC-tail, Ryzen-tuned) over floor-low (portable release) at the pessimistic corner, so the disposition is made against the pessimistic corner, not the reference-library-vs-native-build flattering pairing.

**Optimistic-error guard (Phase 2):** reporting the ASIC/tuned tail as zero (or the floor as its native-build best case) is the optimistic error. The guard *is* the two-ended range: the disposition consumes the pessimistic corner.

---

## 6. Phase 3 — live asymmetry rehearsal (alpha testnet)

**Purpose:** the part a harness cannot produce — inject the Phase-1-measured asymmetry into a live network and observe consensus behavior. This is the genesis 51%-via-asymmetry attack executed where it is free.

### 6.1 Topology and the isolation contract
- A patched/tuned-XMRig (or C-full) **"whale"** runs as a **separate out-of-daemon process pointed at RPC** — it does **not** link the C or XMRig surface into `shekyld`, preserving the `nm` symbol-isolation contract (`scripts/ci/check_randomx_symbol_isolation.sh`: the daemon embeds only the Rust verifier `shekyl_pow_randomx_v2_hash`; the C `randomx_*` surface is contractually absent). The whale talks to the network the way any external miner would.
- Honest miners run **light-mode** (`shekyl-pow-randomx`, the shipped floor).
- Whale hashrate ÷ honest hashrate = the **Phase-1-measured ratio** (injected at the *pessimistic end* of the Phase-2 ceiling range — see guard).
- Network substrate: **regtest / fakechain** (`cryptonote_core.cpp:84-91,335-336,472-473`), driven via the `tests/stressnet/` `load_generator.py` `DaemonRPC` client and the `generateblocks` RPC (`core_rpc_server.cpp:1953`, gated `REGTEST_REQUIRED`). Difficulty read via `get_info` (`:368`) / `getblocktemplate` (`:1597`); blocks via `submitblock` (`:1894`).

### 6.2 Instrument these consensus properties
**Read `tests/difficulty/lwma1_cross_check.cpp` first** — it defines the LWMA cross-check discipline this phase leans on (vectors 6–7 are the load-bearing anti-selfish-mine property: Shekyl's hybrid running-max output must *strictly differ* from canonical zawy12). The production algorithm is `lwma1_next` (`rust/shekyl-difficulty/src/lwma1.rs:62`; `N=90`, `T=120 s`, symmetric ±6·T clamp, N·N·T/20 floor).

| Property | What to observe | Anchor |
|----------|-----------------|--------|
| LWMA response to a sudden large-hashrate **join** and **departure** | does difficulty absorb without oscillation? | `lwma1.rs:62`; discipline in `tests/difficulty/lwma1_cross_check.cpp` |
| **Orphan rate** for light miners while the whale is present | fraction of honest blocks orphaned | block-submit path `on_submitblock` |
| **Selfish-mining / block-withholding** feasibility at the observed ratio | can the whale withhold and win the race? | anti-selfish-mine vectors 6–7 |
| **Time-to-restabilize** after the whale leaves | blocks/seconds until difficulty re-tracks honest hashrate | `lwma1.rs` window `N=90` |
| **Seed-epoch rollover under load** | does an epoch boundary stall verification under whale pressure? | `seed_epoch.rs` (`SEEDHASH_EPOCH_BLOCKS=2048`, `LAG=64`); eager-derive `pow_randomx_ffi.rs:263`; regtest fast-epoch override guarded fakechain-only `blockchain.cpp:582-599` |

Cross-check the block-arrival **stall detector** (`cryptonote_core.cpp:1781-1835`, calibration pinned by `tests/unit_tests/stall_detection_calibration.cpp:121`) is not falsely tripped by the whale's arrival/departure transients.

**Optimistic-error guard (Phase 3):** the chain looks *safer than it is* if the whale is **under-injected** — i.e. if Phase 1 understated the ratio or Phase 2's tail was ignored. Guard: inject at the **pessimistic end** of the ceiling range (ASIC-tail-aware), not the software-reference end; and run the rollover-under-load case specifically, since a boundary stall is exactly where a marginal ratio becomes decisive.

### 6.3 Named gap (do NOT hide behind "talks to the network like any external miner"): the whale must produce *Shekyl* blocks, not just matching hashes
§3.1's constant identity discharges only that XMRig computes the same RandomX-v2 hash *over a given blob* — necessary, but the whale must produce **blocks the Shekyl network accepts**, and that is a strictly larger requirement. Shekyl's block carries PQC fields, FCMP++, and a custom seed schedule; its `getblocktemplate`/`submitblock` dialect and its **block-hashing-blob framing** are Shekyl's, not Monero's. XMRig 6.26.0's "RandomX v2 / FCMP++" support is for *Monero's* v2 — different version bytes, different template. So the whale is **not** free: either

- **(i)** XMRig is patched to Shekyl's stratum/template + blob framing — which **reintroduces exactly the fork-maintenance duty §3.1 avoided**, now for the test harness; or
- **(ii)** the whale is a **Shekyl-aware template shim** that pulls a valid template via RPC (`get_block_template` → `blockhashing_blob`, `core_rpc_server.cpp:1544-1680`), feeds the blob to XMRig-speed hashing, and assembles the winning nonce into a Shekyl-valid block via `submitblock`/`generateblocks` — keeping XMRig stock but owning the Shekyl-block glue ourselves.

This is the **highest-uncertainty item in the plan** and a first-class Phase-0→Phase-3 scoping task, not a throwaway line. Its answer is itself a disposition input: **if making a fast miner emit Shekyl blocks is hard *for us with the source*, it is friction for an attacker too** — a genuine, if fragile, floor that (c)'s "accept the gap" posture may partly lean on. **But the asymmetry cuts toward less comfort than it first reads (sharpening):** the glue is a **one-time cost the attacker pays once and reuses forever**, while the friction only holds during the shallow-work window *if no attacker has paid it yet*. It is real friction against a **low-effort opportunist**, and **near-zero against a motivated genesis adversary** — who is by definition determined (a genesis 51% is a deliberate act). So §6.3 raises the floor against drive-by attackers; it must **not** be cited as a defense against the very threat model this investigation exists for. Scope it explicitly before Phase 3; do not assume stock XMRig-in-daemon-mode drives Shekyl until the blob framing is verified to match at runtime (this is the same runtime-framing question §3.2 flags, surfacing again at the block layer).

### 6.4 The rehearsal measures dynamics; the go/no-go needs threshold arithmetic it cannot produce
Phase 3 answers *"does the chain survive a whale of size X"* (dynamics: LWMA absorption, orphan rate, selfish-mining, restabilize time). It does **not** answer *"what X does an attacker actually achieve"* — that is arithmetic, and its decisive input is **the honest network's size at Shekyl genesis**, which the rehearsal cannot manufacture. The per-box ratio **R** means an attacker needs roughly `honest_boxes / R` boxes to match the network (and a fraction of that with an ASIC). For a privacy-maximalist pre-genesis coin whose honest miners run the light interpreter, that network could be **dozens of hobbyists at launch** — which makes even a single tuned box, let alone an ASIC, a plausible majority. So the threshold arithmetic — `R × plausible-attacker-hardware` vs `plausible-honest-network-at-genesis`, **with the network-size assumption stated explicitly** — is a distinct deliverable (§7 item 6). Phase 3 (survival at size X) and this arithmetic (what X is reachable) are **both** required; the rehearsal alone is only half the answer.

---

## 7. Deliverables

1. **Phase 0 fork-delta finding** + the ceiling-artifact decision (stock / patched / forked XMRig), with the three-way byte-equality differential passing **and** the §6.3 scoping of what it takes to make the ceiling miner emit *Shekyl* blocks (patched-XMRig vs template-shim).
2. **The factorial table** — five (or six) points, the **four decomposed factors** (dataset / JIT / memory-tuning / language), and the **two efficiency axes** (H/watt, H/$) — full provenance (§2) per number, aggregate-H/s basis. Create `docs/design/LATENCY_RATIO_BUDGET.md` here and close the `PHASE3_PLAN:548` dangling reference (§1.2).
3. **The asymmetry stated as a two-ended range** — ceiling-high (ASIC-tail, Ryzen-tuned) over floor-low (portable release) at the pessimistic corner — with the **unmeasured-headroom**, **ASIC-threat-class-live**, and **floor-spread** statements (§5, §5.1).
4. **The live-rehearsal results** against the instrumented consensus properties (§6).
5. **The threshold arithmetic** (§6.4): `R × plausible-attacker-hardware` vs `plausible-honest-network-at-genesis`, **with the genesis network-size assumption stated explicitly** — the piece that converts R into a go/no-go the rehearsal cannot produce.
6. **A synthesis** mapping the evidence to the three disposition options, each with what the numbers say **for and against** — *feeding, not making*, the maintainer decision, recorded with the §10 reopen criterion.

---

## 8. Ordering / gating (do not parallelize past a gate)

```
Phase 0  ──(XMRig clone pinned + 3-way differential passes)──▶  gates:
   ├─▶ Phase 1 ceiling leg (XMRig point)
   └─▶ Phase 3 whale (needs a correct ceiling miner)

Phase 1  ──(measured ratio + decomposed factors)──▶  sizes:
   └─▶ Phase 3 injection ratio     and     §9 early-prototype decision

Phase 2  ──(ceiling range, pessimistic tail)──▶  refines:
   └─▶ Phase 3 injection ratio (inject at pessimistic end)
```

- **Phase 0 gates Phase 1's ceiling leg and Phase 3's whale.** A ceiling from an unverified/wrong-hash miner is disqualifying.
- **Phase 1 sizes Phase 3's injection ratio.**
- Phases 0→1→(2,3) are serial across their gates. Within Phase 1, the five floor/ceiling *points* can be measured concurrently on the fixed machine (same hardware, so no cross-contamination), but the **XMRig point** waits on the Phase 0 gate.

---

## 9. Early flag — is the Rust-dataset-mode prototype worth standing up *during* the study?

`shekyl-pow-randomx` currently **never materializes a dataset** — the Phase 0 "no dataset" decision (`vm.rs:355-357`; `RANDOMX_V2_RUST.md` §6). So "Rust-full" is genuinely unbuilt.

**Decision rule (pinned to the security requirement, not a vague fraction — R3):** the greenlight is **not** "closes most of the gap" — "most" is undefined, and an undefined trigger on a build-or-don't decision is exactly where scope creep enters (and where rerun-until-satisfied hides). It is: **if the upper bound `dataset-factor × Rust-light` reaches the floor level that the §6.4 threshold arithmetic says is needed to survive the plausible-genesis-network attack**, build the Rust-dataset prototype **during** the investigation — turning disposition option (a) from *hypothetical* into *measured* (add the "Rust-full" point to §4.1). This ties the prototype decision to *does this floor survive the threat model*, not to a fraction of an engineering gap. The threshold is the **§6.4 output** (it depends on the genesis-network-size assumption), not a free parameter set here. That is the get-it-right shape — the maintainer decides against a real number, not a projection. **Flag this to the maintainer the moment the dataset factor lands**, before Phase 3, so the prototype (if greenlit) can be measured on the same fixed machine under the same provenance.

**Caveat on the projection (per §4.2):** `dataset-factor × Rust-light` is an **upper bound** on Rust-full's floor, not the floor it delivers — Rust-full inherits the *dataset* factor but **not** the *memory-tuning* factor (1 GiB pages, MSR: privileged, and off-limits to a `#![deny(unsafe_code)]` verifier without an architectural change). So the projection tells you the *best* option (a) could do; if even that upper bound doesn't close the gap, option (a) is out without building it. If it does, the prototype is worth standing up precisely to find out how far below the upper bound the safe-Rust reality lands.

---

## 10. Disposition options + reopen criterion (§21)

The synthesis (deliverable 5) maps evidence to three options — **it does not choose**:

| Option | Raises the floor by | For | Against |
|--------|--------------------|-----|---------|
| **(a) First-party Rust dataset/full-mem mode** | giving honest miners the dataset (and possibly JIT) fast path in the shipped Rust code | keeps the all-Rust, C-absent-from-consensus posture; floor rises without blessing external C | revisits the `RUST.md` §6 no-dataset/no-prewarm decision; ~2 GiB per verifier; build+verify cost (measured by §9 if prototyped); **cannot reach the memory-tuning factor (1 GiB pages, MSR) without abandoning `#![deny(unsafe_code)]` (F1) — so the dataset factor is the *ceiling* of what it buys, and it still trails a Ryzen-tuned attacker on that axis** |
| **(b) Bless a reference XMRig** | pointing honest miners at the same fast C miner the adversary uses | fastest floor with least Shekyl code; miners already exist; the honest floor gets the memory-tuning factor option (a) can't | distribution/trust/fork-pin duty for an external C artifact; a blessed miner is a supported surface (though out-of-daemon, so the `nm` contract still holds); **the Shekyl-block-production work (§6.3) is needed for the whale regardless, and blessing means *owning* that miner↔Shekyl glue as a shipped, maintained surface** |
| **(c) Accept the gap, documented difficulty/checkpoint posture** | not raising the floor — bounding the *window* instead (genesis checkpoints / slow-start difficulty / rolling checkpoints through the shallow-work era) | zero miner/verifier change | "do nothing on the floor" is itself a security choice with a threat model; checkpoints are a centralization cost during the window; **the §6.3 "attacker-must-build-Shekyl-glue" friction it may lean on protects against opportunists, not the motivated genesis adversary (one-time cost, reused forever) — so it is not a substitute for the checkpoint posture against the deliberate 51%** |

**Reopen criterion (rule 21):** whichever option is chosen — **including (c)** — is recorded with an explicit reopen trigger, because "accept the gap" is not a null choice. Candidate triggers: measured asymmetry exceeding a named multiple at the pessimistic ceiling; observation of a Shekyl-repurposed RandomX ASIC in the wild; a Phase-3 rehearsal showing the chain does *not* survive the injected ratio. The disposition names which commitment binds (security precondition) and why.

---

## 11. Red-team rounds — findings disposition

Structured adversarial passes on the measurement design (2026-07-05). All findings accepted and integrated — none touched the phase gating, provenance protocol, pessimistic-error discipline, or doc-doesn't-decide posture; they corrected what would otherwise have been a subtly wrong ceiling on a consensus-security decision. Recorded, not silently folded, per this program's review-disposition discipline.

### 11.1 Round 1 (F1–F7 — HIGH/MED structural)

| # | Sev | Finding | Disposition / where it landed |
|---|-----|---------|-------------------------------|
| F1 | HIGH | The decomposition missed a **fourth factor** — memory-subsystem tuning (1 GiB huge-pages + MSR/prefetcher) — that a `deny(unsafe)` Rust verifier can't reach, so the §9 extrapolation over-predicts option (a). (Its independence was over-stated; corrected by R1.) | **Integrated:** four-factor decomposition (§4.2, tuning factor + LARGE_PAGES/MSR toggle isolation); §9 upper-bound caveat; §10(a) cost; §2 Ryzen-favouring hardware caveat (optimistic-error). |
| F2 | HIGH | The whale conflates "matching hash" (discharged) with "produces a **Shekyl block**" (not discharged) — Shekyl's template/blob framing ≠ Monero's; needs patched-XMRig or a template shim. Largest hidden scope risk. | **Integrated:** §6.3 named gap with two options (patched vs shim); folded into deliverable 1 and §10(b) cost; tied to the §3.2 runtime-framing caveat. |
| F3 | HIGH | Floor (single-thread-inverted) and ceiling (optimal-threads) measured at **mismatched thread configs** — not like-for-like for a bandwidth-bound PoW; dataset factor is a curve over thread count. | **Integrated:** §4.3 aggregate-H/s ratio basis + dataset-factor-as-curve; thread-count first-class in §2; single-thread firewalled to the T5 verification budget. |
| F4 | MED | The interleaved same-process ratio method **cross-contaminates** when footprints mismatch (2 GiB dataset VM vs 256 MiB light VM evict each other). | **Integrated:** §4.3 — interleave only the footprint-matched language factor; measure mode factors sequentially with teardown. |
| F5 | MED | The rehearsal measures **dynamics**; the go/no-go needs **threshold arithmetic** (R × attacker-hw vs honest-network-at-genesis) whose missing input is the **genesis network size**. | **Integrated:** §6.4 + deliverable 5 — threshold arithmetic with the network-size assumption stated explicitly. |
| F6 | MED | The **floor is a range too** (portable release ↔ native-from-source); pessimistic ratio pairs floor-low with ceiling-high. | **Integrated:** §5.1 + §5 output + deliverable 3 — two-ended range, pessimistic corner. |
| F7 | LOW | Reframe the ASIC question from "will an X9 repurpose" (uncertain) to "**is the ASIC design-capability threat class live**" (certain); keep H/watt (stable) distinct from H/$ (market-drift). | **Integrated:** §5 point 2 (threat-class-live footing); §4.4 (two distinct efficiency axes). |

### 11.2 Round 2 (R1–R4 residuals + two sharpenings — LOW, polish-while-open)

| # | Finding | Disposition / where it landed |
|---|---------|-------------------------------|
| Sharpen-1 | The §2 Ryzen-tuning caveat reads as a permanent hedge; it has a discharge path (the 9950X3D rig converts it to a measured number). | **Integrated:** §2 two-machine plan — Intel-first, re-measure the tuning factor + ceiling on Ryzen, Intel↔Ryzen spread is itself a datum; the caveat is labeled floor-pending-Ryzen (direction known, magnitude pending). |
| Sharpen-2 | §6.3's "hard for us ⇒ friction for attacker" is asymmetric — a one-time cost the attacker pays once and reuses; protects vs opportunists, near-zero vs the *motivated* genesis adversary. | **Integrated:** §6.3 annotation; §10(c) row — friction is not a substitute for the checkpoint posture against the deliberate 51%. |
| R1 | The four factors are **not** cleanly orthogonal — tuning×dataset interact (huge-pages help *because* of the 2 GiB dataset), so the product won't equal the measured endpoints. | **Integrated:** §4.2 — measure the total gap (Rust-light-floor ÷ XMRig-ceiling) *directly* as ground truth; the four factors are an explanatory breakdown; a large product-vs-direct residual is itself a finding (built-in factorial cross-check). |
| R2 | §3.2's differential blurs two layers — hash-core (raw-blob) vs block-framing; the existing corpus is raw-blob, and §6.3 established XMRig can't be driven on raw Shekyl blocks without the shim. | **Integrated:** §1.4 (two-layer split), §3.2 (hash-core proof at raw-blob layer, `randomx_calculate_hash`/hash-dump, `corpus_random.rs` is correct *here*), §3.3 (not template-mining); block-framing equivalence is the separate §6.3 deliverable. |
| R3 | §9's greenlight ("close *most* of the gap") has no numeric threshold — an undefined build-or-don't trigger invites scope creep. | **Integrated:** §9 — greenlight pinned to the §6.4 threshold arithmetic (upper bound reaches the floor needed to survive the plausible-genesis-network attack), tying the prototype decision to the security requirement, not a fraction. |
| R4 | 1 GiB huge-page reservation can *silently* fall back to 2 MiB → understated tuning factor (optimistic error). | **Integrated:** §2 provenance — reservation must be *confirmed successful, not merely requested* (the miner logs the page size used); same class as the confirmed-`FLAG_V2` guard. |

---

## Appendix A — source anchor map (verified at `dev` = `d05d64666`)

**RandomX Rust crates**
- `rust/randomx-v2-sys/` — the only crate linking the C lib; `build.rs:64-74` (`rustc-link-lib=static=randomx` + C++ runtime), gated on `RANDOMX_V2_INSTALL_DIR` (`build.rs:62`, soft-fail `:76-93`); fork pin `Cargo.toml:48-49` (`aaafe71`). Light-mode surface = 7 symbols, `src/lib.rs:169-222`; dataset/JIT deliberately unbound `src/lib.rs:75-80`. Flags `src/lib.rs:120-167` (`RANDOMX_FLAG_DEFAULT=0` `:129`, `RANDOMX_FLAG_V2=128` `:167`).
- `rust/shekyl-pow-randomx/` — pure-Rust verifier; entry `src/lib.rs:196` (`compute_hash`); no dataset materialization `src/vm.rs:355-357`. Benches `benches/{compute_hash_alloc,per_call_alloc,cache_derive}.rs` (criterion, `harness=false`, pure-Rust light).
- `rust/shekyl-randomx-differential/` — harness; sole consumer of `randomx-v2-sys` (`Cargo.toml:78-79`, enforced by `tests/crate_invariants.rs`). Correctness driver `src/mode_correctness.rs:272`; C oracle `src/c_oracle.rs:281-317` (`RANDOMX_FLAG_DEFAULT` alloc `:290`, `RANDOMX_FLAG_V2`+NULL-dataset VM `:305`); latency `src/mode_latency.rs`; corpus `src/corpus_random.rs:57` (seed `shekyl-randomx-differential-corpus-v1`), 16×8 per-PR / 32×32 nightly.

**Consensus seam / isolation**
- Daemon PoW call `src/crypto/pow_randomx.cpp:16-21` → `shekyl_pow_randomx_v2_hash`; Rust export `rust/shekyl-ffi/src/pow_randomx_ffi.rs:192-230`; C header `src/shekyl/shekyl_ffi.h:2037`. `nm` isolation `scripts/ci/check_randomx_symbol_isolation.sh` (banned C `randomx_*` list `:76`; required Rust export check `:97`). Consensus stub (do NOT route benches through it) `rust/shekyl-consensus/src/randomx.rs:16-52`.

**Parity / Hole-1 (C-full + miner KAT)**
- `RANDOMX_V2_PHASE3_PLAN.md:436` §7 (C-full vs Rust-light); miner KAT `tests/randomx_v2_parity/randomx_v2_miner_kat.cpp` (`randomx_v2_full_parity_miner_kat`), full parity `tests/randomx_v2_parity/randomx_v2_full_parity.cpp`. CI: `randomx-v2-differential.yml` (T5 daily), `randomx-v2-adversarial-ratio.yml` (T6 weekly).

**Difficulty / LWMA**
- `rust/shekyl-difficulty/src/lwma1.rs:62` (`lwma1_next`; clamp `:97-98,125`; floor `:142`); consts `src/consts.rs:22,32` (`N=90`, `T=120`); JSON source `config/consensus_constants.json:9-13`. C++ call path `src/cryptonote_core/blockchain.cpp:129,192,1008,1095`. Cross-check `tests/difficulty/lwma1_cross_check.cpp` (monotonic vectors 1–5; anti-selfish-mine vectors 6–7 `:176-188`).

**Testnet / RPC**
- regtest/fakechain `src/cryptonote_core/cryptonote_core.cpp:84-91,335-336,472-473`. RPC `src/rpc/core_rpc_server.cpp`: `getblocktemplate:1597`, `submitblock:1894`, `generateblocks:1953` (gated `:1963`), `get_info:368`. Stressnet `tests/stressnet/load_generator.py:60` (`DaemonRPC`).

**Seed epoch**
- `rust/shekyl-pow-randomx/src/seed_epoch.rs` (`SEEDHASH_EPOCH_BLOCKS=2048` `:46`, `LAG=64` `:48`, `seedheight` `:109`). FFI/eager-derive `rust/shekyl-ffi/src/pow_randomx_ffi.rs:263-278`. Regtest fast-epoch override (fakechain-only) `src/cryptonote_core/blockchain.cpp:582-599`. Stall detector `src/cryptonote_core/cryptonote_core.cpp:1781-1835`, calibration `tests/unit_tests/stall_detection_calibration.cpp:121`. Drift sentinel `tests/unit_tests/seed_epoch.cpp:31`.

**External artifacts (pins)**
- `external/randomx-v2` @ `aaafe71` (v2.0.1, pristine tevador — working tree clean, no `shekyl` markers). `/home/torvaldsl/shekyl/RandomX` @ `0720fe4d` (dev-tooling atop `aaafe71`; `configuration.h` byte-identical). **XMRig @ `b2ca7248` (v6.26.0)** at `/home/torvaldsl/shekyl/xmrig` — present; `RX_V2` config `src/crypto/rx/RxAlgo.cpp:35-36` → `RandomX_MoneroConfigV2` (`src/crypto/randomx/randomx.cpp:55-62`), base defaults `randomx.cpp:124-133` / `randomx.h:70-76`. Constant delta vs fork = **none** (§3.1). Release-watch duty: re-pin deliberately on any bump.

---

## Appendix B — results

*No timing number is entered without its full §2 provenance. Phases 1–3 pending; Phase 0's correctness result below is hardware-independent (a hash either matches or it doesn't), so the dev box is a valid site for it.*

### B.0 Phase 0 — XMRig-ceiling hash-core differential (2026-07-06)

| Field | Value |
|-------|-------|
| Result | **1024 / 1024 pairs byte-identical, 0 mismatches** (full corpus). Single-vector KATs: `--rx0` (v1 build-faithfulness) = `639183aa…` exact; `--kat-full` (v2, full dataset) = `34f8b017…` == canonical. |
| Miner | XMRig **6.26.0** @ `b2ca7248`, RandomX sources compiled with `-DXMRIG_FEATURE_ASM` (x86-64 JIT), **software AES**, Argon2 generic arch; config `RandomX_ConfigurationMoneroV2` (ProgramSize 384 + 4 tweaks). |
| Mode | **full-dataset (`FULL_MEM｜JIT`)** — the adversary's mining mode. XMRig's light/interpreter path is v2-incomplete (`2fe105f9…`) and must not be used. |
| Reference | Shekyl `CANONICAL_RANDOM_HASHES` (`canonical_outputs.rs`), fork `external/randomx-v2` @ `aaafe71`, via `parity_corpus.dat` SHA-256 `713d5702…03ba`. |
| Corpus | nightly 32 seedhashes × 32 blobs = 1024 raw-blob pairs (`corpus_random.rs`, seed `shekyl-randomx-differential-corpus-v1`). |
| Build/host | g++/gcc 14.2 (Debian), `-O2 -std=c++17`; dev box `i9-11950H`. ~16 min (32 × 2 GiB dataset inits, single-thread). |
| Artifact | [`tests/randomx_v2_parity/xmrig_ceiling/`](../../tests/randomx_v2_parity/xmrig_ceiling/) (`build.sh`, `xmrig_parity.cpp`, `support.cpp`, `README.md`). |

*This is a correctness result (hash equality), not a timing/ratio number — those are Phase 1 and require the two-machine plan (§2).*
