# Electrum-words removal — CryptoNote 25-word mnemonic subsystem deletion from genesis

**Status.** **DRAFT — Round 1 (initial draft, 2026-05-19).** Phase 0
deliverable for the Electrum-words (CryptoNote-25-word mnemonic)
subsystem removal. Companion:
[`ELECTRUM_WORDS_REMOVAL_PLAN.md`](./ELECTRUM_WORDS_REMOVAL_PLAN.md).
Both documents must close the Phase 0 review cycle (target 4–6
rounds per `20-rust-vs-cpp-policy.mdc`) before any deletion code
lands.

**Scope.** Shekyl genesis ships BIP39-only for wallet seed
material. The inherited CryptoNote 25-word "Electrum-style"
mnemonic format and its 14-language word-list infrastructure are
deleted, not version-dispatched. The Phase 0 Mission Audit Lens B
finding B-1 designates this work as a pre-genesis deletion per
`60-no-monero-legacy.mdc` and `16-architectural-inheritance.mdc`.
The user-fiat decision (recorded in the audit substrate as
`b1_disposition_settled_delete`): shekyl-gui-wallet,
shekyl-mobile-wallet, and shekyl-web will route through the
existing Rust BIP39 FFI bridge regardless of their current state.

---

## 1. Inheritance disposition

### 1.1 Why this is Rule-60 residue

The CryptoNote 25-word mnemonic format is a CryptoNote-era seed
encoding inherited via Monero. Per
[`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc),
Shekyl begins at its own genesis with no pre-genesis blocks to
validate and no users with legacy wallet state. Inherited code
that exists solely to handle pre-genesis Monero/CryptoNote
behaviour is dead weight; the rule's enumeration of "removed from
construction and verification" does not list the mnemonic
subsystem only because the audit had not yet enumerated it.

The Electrum-words subsystem satisfies all three deletion
criteria from
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc):

1. **No Shekyl users with Electrum-words seeds exist.** Pre-genesis,
   there is no installed base. The `rm -rf ~/.shekyl` migration path
   covers any developer-side test wallets.
2. **The replacement primitive already ships.** BIP39 is already the
   canonical seed path on the Rust side, exported via the
   `shekyl_bip39_*` and `shekyl_account_generate_from_bip39` FFI
   functions (see §3.1).
3. **Carrying both paths is a permanent attack surface for a one-time
   problem.** Keeping a 25-word path "for compatibility" creates a
   second seed-derivation surface that auditors must reason about
   forever, when no consumer of Shekyl at genesis depends on it.

### 1.2 Architectural-inheritance framing

Per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc),
the inherited Electrum-words code is *correct for Monero* (where
millions of pre-existing wallets use it) and *wrong for Shekyl*
(where zero pre-genesis wallets exist). The Monero code's
architecture — 14 language word lists, a CryptoNote checksum
scheme, a custom binary-to-words encoder — is well-tested in its
original context but contradicts Shekyl's pre-genesis posture.

This is the "inheriting code is not inheriting architecture"
finding made concrete: the audit's job is to surface that the
code's architecture (multi-language mnemonic infrastructure
serving pre-existing CryptoNote users) does not deliver against
Shekyl's threat model (one user base, one mnemonic standard,
BIP39 as universal industry default).

### 1.3 Where this sits relative to the Phase 0 Mission Audit

The Phase 0 Mission Audit (closed 2026-05-17) surfaced this work
as Lens B finding B-1: *"wallet2::is_deterministic + get_seed
chain on Monero-era 25-word mnemonic format; user-fiat: GUI/mobile
will route through BIP39"*. Per the audit's `audit_trajectory_ratio_observation`
pin, the audit's job was *finding* inherited architecture that
contradicts the threat model; *executing* the migration is the
work this PR series defines.

This PR (Phase 0) plus four implementation PRs (Phases 1–6 across
five PRs total per §5.2 of the plan doc) close out the B-1 audit
finding. No follow-up audit work is expected; the symbol-isolation
CI invariants (§7) become the structural compliance check that
makes future re-acquisition of Electrum-words surface detectable.

---

## 2. Deletion surface inventory

The total deletion surface is enumerated here so the per-phase PR
descriptions can cite this section rather than re-enumerating.
Line numbers are accurate as of `dev` tip after merges of PR #46
(audit substrate), PR #47 (Batch α PR 1 / Cargo.toml zeroize
features), PR #48 (Batch α PR 2 / ring_size cleanup), PR #53
(LWMA-1 Phase 4), and PR #54 (RandomX v2 Phase 1). Re-verify
against `dev` tip at each phase's branch-cut time.

### 2.1 Mnemonics subsystem (`src/mnemonics/`)

Entire directory. 14 language word-list headers (~480 KB
combined):

```text
src/mnemonics/chinese_simplified.h    src/mnemonics/japanese.h
src/mnemonics/dutch.h                 src/mnemonics/lojban.h
src/mnemonics/english.h               src/mnemonics/portuguese.h
src/mnemonics/english_old.h           src/mnemonics/russian.h
src/mnemonics/esperanto.h             src/mnemonics/spanish.h
src/mnemonics/french.h
src/mnemonics/german.h
src/mnemonics/italian.h
```

Plus the implementation + framework files:

```text
src/mnemonics/CMakeLists.txt
src/mnemonics/electrum-words.cpp
src/mnemonics/electrum-words.h
src/mnemonics/language_base.h
src/mnemonics/singleton.h
```

Plus the test file:

```text
tests/unit_tests/mnemonics.cpp
```

Total: 21 files deleted, ~570 KB.

### 2.2 wallet2 core methods

| File | Symbol | Disposition |
| --- | --- | --- |
| `src/wallet/wallet2.h:1001` | `bool is_deterministic() const` | Delete declaration |
| `src/wallet/wallet2.h:1002` | `bool get_seed(epee::wipeable_string&, const epee::wipeable_string&)` | Delete declaration |
| `src/wallet/wallet2.h:1007` | `const std::string &get_seed_language() const` | Delete declaration |
| `src/wallet/wallet2.h:1011` | `void set_seed_language(const std::string&)` | Delete declaration |
| `src/wallet/wallet2.cpp:1362` | `bool wallet2::is_deterministic() const` body | Delete definition |
| `src/wallet/wallet2.cpp:1372` | `bool wallet2::get_seed(...)` body | Delete definition |
| `src/wallet/wallet2.cpp:1425` | `const std::string &wallet2::get_seed_language() const` body | Delete definition |
| `src/wallet/wallet2.cpp:1433` | `void wallet2::set_seed_language(const std::string&)` body | Delete definition |

The internal `wallet2::generate()` and `wallet2::restore()`
Electrum-words branches at `src/wallet/wallet2.cpp:600–669` are
the Phase 1 rewire targets: the `crypto::ElectrumWords::*` calls
in this range are replaced by `shekyl_bip39_*` /
`shekyl_account_generate_from_bip39` FFI calls per §3.1, and the
`language` / `old_language` local variables become unused (and
are deleted alongside the parameter at Phase 3).

### 2.3 wallet2 state and JSON ser/de

| File | Line | Disposition |
| --- | --- | --- |
| `src/wallet/wallet2.h:1728` | `std::string seed_language;` field | Delete field (Phase 4 Commit C) |
| `src/wallet/wallet2.cpp:4793–4802` | JSON write of `seed_language` | Delete (Phase 4 Commit B) |
| `src/wallet/wallet2.cpp:5344–5347` | JSON read of `seed_language` | Delete (Phase 4 Commit B) |
| `src/wallet/wallet2.cpp:6479` | Comment `"Pre-v1 wallets (legacy 25-word Electrum seed…)"` | Delete (Phase 4 Commit A, or earlier as opportunistic) |

### 2.4 RPC surface

| RPC command | File | Line | Disposition |
| --- | --- | --- | --- |
| `COMMAND_RPC_GET_LANGUAGES` | `src/wallet/wallet_rpc_server_commands_defs.h:2074` | struct + handler | Delete (Phase 2) |
| `COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET` | `src/wallet/wallet_rpc_server_commands_defs.h:2223` | struct + handler | Delete (Phase 2) |
| `COMMAND_RPC_QUERY_KEY` mnemonic branch | `src/wallet/wallet_rpc_server.cpp` query_key dispatch | conditional | Delete `"mnemonic"` branch; preserve string-key (see §4.5 disposition) only as a Rust-routed BIP39 reply path |
| `get_wallet_words` handler | `src/wallet/wallet_rpc_server.cpp:2214,2220` | handler body | Delete (Phase 2) |
| Language-set handlers | `src/wallet/wallet_rpc_server.cpp:3661,4082` | language-validation branches | Delete (Phase 2) |
| Electrum-words restore branches | `src/wallet/wallet_rpc_server.cpp:2324–2358, 4162–4225` | `words_to_bytes` and `get_is_old_style_seed` calls + explanatory comments | Delete (Phase 2) |

### 2.5 FFI surface

| FFI symbol | File | Disposition |
| --- | --- | --- |
| `wallet2_ffi_restore_deterministic_wallet` | `src/wallet/wallet2_ffi.h:98–104` + `wallet2_ffi.cpp:414–431` | Delete entire function (Phase 3) |
| `wallet2_ffi_create_wallet` `language` parameter | `src/wallet/wallet2_ffi.h:87` + `wallet2_ffi.cpp:309–319` | Drop parameter (signature change; Phase 3) |
| `wallet2_ffi_generate_from_keys` `language` parameter | `src/wallet/wallet2_ffi.h:113` + `wallet2_ffi.cpp:523–527` | Drop parameter (signature change; Phase 3) |
| `query_key("mnemonic")` dispatch branch | `src/wallet/wallet2_ffi.cpp:648,653` | Replace with hard error (Phase 1) → delete branch (Phase 4) |
| Language-list export | `src/wallet/wallet2_ffi.cpp:1197–1198` | Delete (Phase 3) |
| `crypto::ElectrumWords::words_to_bytes` + `is_valid_language` calls | `src/wallet/wallet2_ffi.cpp:309,416,429,523` | Delete (Phase 3) |

### 2.6 Build system

| File | Change |
| --- | --- |
| `src/CMakeLists.txt` | Remove `add_subdirectory(mnemonics)` |
| `src/mnemonics/CMakeLists.txt` | Delete entire file |
| `src/wallet/CMakeLists.txt` | Remove `mnemonics` from link dependencies (if listed) |
| `tests/unit_tests/CMakeLists.txt` | Remove `mnemonics.cpp` from test sources |

### 2.7 Tests

| File | Disposition |
| --- | --- |
| `tests/unit_tests/mnemonics.cpp` | Delete entire file (Phase 5) |

Any wallet-creation / wallet-restore integration tests that pass
`language="English"` are updated to drop the `language` parameter
(Phase 3 alongside the FFI signature change).

### 2.8 Includes audit

The `#include "mnemonics/electrum-words.h"` directive appears at:

- `src/wallet/wallet2.cpp:79`
- `src/wallet/wallet2_ffi.cpp:38`
- `src/wallet/wallet_rpc_server.cpp:64`

All three are deleted in their respective phases (Phase 1 for
wallet2.cpp internal cleanup; Phase 2 for wallet_rpc_server.cpp;
Phase 3 for wallet2_ffi.cpp).

---

## 3. BIP39 replacement path

### 3.1 Existing FFI bridge

The C++ → Rust BIP39 bridge already exists in the workspace and
is wired into production code paths. Per `src/shekyl/shekyl_ffi.h`:

```c
// src/shekyl/shekyl_ffi.h
bool shekyl_bip39_validate(const uint8_t* words_ptr, size_t words_len);
bool shekyl_bip39_mnemonic_from_entropy(
    const uint8_t* entropy, size_t entropy_len,
    uint8_t* words_out, size_t words_cap, size_t* words_len_out);
bool shekyl_bip39_mnemonic_to_pbkdf2_seed(
    const uint8_t* words_ptr, size_t words_len,
    const uint8_t* passphrase_ptr, size_t passphrase_len,
    uint8_t* seed_out_64);
bool shekyl_account_generate_from_bip39(
    const uint8_t* words_ptr, size_t words_len,
    const uint8_t* passphrase_ptr, size_t passphrase_len,
    uint8_t network,
    uint8_t* seed_out_64,
    /* … account-blob output parameters … */);
```

Rust implementations live in `rust/shekyl-ffi/src/account_ffi.rs`
at lines 134, 163, 212, 584. `src/cryptonote_basic/account.cpp`
already calls these (the bridge is in production, not test
scaffolding). No Phase 1 prerequisite work is required to wire
the call sites; the substitution at
`src/wallet/wallet2.cpp:600–669` is a straight swap of
`crypto::ElectrumWords::*` for `shekyl_bip39_*` /
`shekyl_account_generate_from_bip39`.

### 3.2 Per-consumer migration map

The cross-repo coordination matrix at audit-pre-flight (2026-05-19)
collapses from three consumers to one:

#### 3.2.1 shekyl-gui-wallet (ACTIVE consumer; Phase 3 coordination party)

Substantial Electrum-words integration via `src-tauri/`:

| File | Surface |
| --- | --- |
| `src-tauri/src/wallet_bridge.rs:156–159` | `create_wallet(wallet_path, password, language)` Rust-side wrapper passes `language` to `wallet2_ffi_create_wallet` |
| `src-tauri/src/wallet_bridge.rs:366–377` | `restore_deterministic_wallet(handle, path, seed, password, language, height, seed_offset)` Rust-side wrapper |
| `src-tauri/src/wallet_bridge.rs:475–477` | `query_key(handle, key_type)` dispatcher (calls `wallet2_ffi_query_key`) |
| `src-tauri/src/commands.rs:64,72,498,519,527,613,636,652,666,703,709,714` | Tauri command surface: `language` parameters on import/create flows, `query_key("mnemonic")` for seed display, `SeedInfo { seed, seed_language }` data structure |

Migration shape (Phase 3 coordinated unit):

1. `wallet_bridge.rs::create_wallet` drops `language` parameter; signature becomes `create_wallet(wallet_path, password)`.
2. `wallet_bridge.rs::restore_deterministic_wallet` deleted in its current form; replaced by a wrapper around the new BIP39 entry (whose Rust-side caller routes through `shekyl_account_generate_from_bip39` on the shekyl-core side, since `wallet2_ffi_restore_deterministic_wallet` no longer exists).
3. `wallet_bridge.rs::query_key("mnemonic")` continues to work as the string key (§4.5), but the wallet-side dispatch returns the BIP39 phrase rather than the 25-word Electrum encoding.
4. `commands.rs` Tauri command signatures lose their `language: Option<String>` parameters; the `seed_language: String` field on `SeedInfo` is dropped.
5. UI flows that show a "select seed language" picker before wallet creation are deleted; UI flows that show a 25-word display for backup are repointed to the BIP39 24-word display.

The shekyl-gui-wallet migration PR is a sibling of the shekyl-core
Phase 3 PR; both land coordinated per §5.3.

#### 3.2.2 shekyl-mobile-wallet (FUTURE consumer; no Phase 3 migration)

Pre-flight inspection (2026-05-19) confirms: zero references to
`wallet2_ffi`, `restore_deterministic_wallet`,
`set_seed_language`, or `electrum` across the entire repo. The
repo has two commits — one Android-first wallet example, one
docs realignment. Not yet a `wallet2_ffi` consumer.

shekyl-mobile-wallet picks up the post-deletion FFI surface
whenever it begins binding to `wallet2_ffi`. No Phase 3
coordination work in this repo.

#### 3.2.3 shekyl-web (NOT a consumer; no Phase 3 migration)

Pre-flight inspection: zero references. Not a `wallet2_ffi`
consumer. Will pick up the post-deletion FFI surface if/when it
begins binding.

### 3.3 Coordination convention for non-active consumers

During B-1 Phase 0 → Phase 3 flight, shekyl-mobile-wallet and
shekyl-web **defer initiating `wallet2_ffi` consumption work**.
Both repos pick up the post-deletion FFI surface (BIP39-only, no
Electrum-words paths) whenever they begin binding. This is a
coordination convention, not a blocker — both repos remain free
to develop other functionality during the flight.

If either repo's roadmap forces a `wallet2_ffi` binding during
B-1 flight, the matrix re-expands to include that repo as a Phase
3 coordination party and the disposition is re-opened per the
reversion clauses in §6.5.

---

## 4. Permanent architectural decisions

These decisions are made now and locked. Any future proposal to
reverse them must start with a new design doc that addresses the
rationale below.

### 4.1 BIP39-only from genesis, no version dispatch

Per `60-no-monero-legacy.mdc`, genesis ships with BIP39 and
nothing else. No `HF_VERSION_BIP39` gate, no fallback to
Electrum-words, no "v1 mnemonic" / "v2 mnemonic" path. Inherited
code that handles pre-genesis 25-word seed material is deleted,
not gated. This matches the LWMA-1 §1 disposition and the
RandomX-v2 §1 disposition.

### 4.2 wallet2::generate() retains orchestrator role; Rust does seed production

Disposition: **(a)** from the Round 1 critical-gap review.
`wallet2::generate()` continues to be the C++ orchestrator of
wallet-file creation (keys → encrypted file persistence; wallet
state initialization; address-book bootstrap), but offloads
seed-production to the Rust BIP39 entry via
`shekyl_account_generate_from_bip39`. Rationale:

1. **Rule 20 rule 1: "Rust if touches a secret."** The BIP39
   mnemonic is the master secret. Per
   [`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
   rule 1, secret-generation logic belongs in Rust.
2. **Rejected: (c) wholesale wallet2::generate() deletion.** That
   shape is the B-3 architectural workstream (Rust owns the
   wallet-file orchestration). Materially larger, multi-quarter,
   not pre-genesis-bounded. B-1 is a bounded deletion, not a
   re-architecture.
3. **Rejected: (b) wallet2::generate() becomes a shim requiring
   pre-generated keys.** Splits responsibility awkwardly between
   "we have keys" and "we make the file"; produces a non-obvious
   call-site contract.
4. **Accepted: (a) wallet2::generate() calls Rust BIP39 entry.**
   Matches the wallet2 cluster (B-2/C-1/C-3/C-4/C-5) stop-gap
   pattern from the audit: wallet2 keeps orchestrating while
   secret-touching operations route to Rust. The B-3 architectural
   workstream subsumes this stop-gap when it lands; until then,
   the (a) shape is the architectural-integrity-now answer per
   `16-architectural-inheritance.mdc`'s `cost-benefit-defer-to-later`
   anti-pattern recognition.

### 4.3 Phase 1 hard-error on non-empty `language` parameter

Phase 1's wallet2 internal-only rewire is **signature-preserving,
behavior-narrowing-to-hard-error** on any non-empty `language`
parameter. Empty / `None` / `nullptr` is the only accepted value.
Non-empty values return an error code (FFI-level) or throw
`tools::error::wallet_internal_error` (RPC-level).

Rationale: the alternative — "silently accept and ignore the
parameter" — is the production-software graceful-degradation
default leaking into a pre-genesis context where the
discipline-correct posture is loud failure. Specifically:

1. Silently-ignored parameters produce a window between Phase 1
   land and Phase 3 land during which consumer code that still
   passes `language="English"` *appears to work*; the parameter
   has no effect, the wallet generates correctly, and the
   consumer ships code that breaks at Phase 3 cutover with no
   prior signal.
2. Hard-error-on-non-empty makes Phase 1 land the discovery
   point for consumer migration. Consumers see the breakage
   immediately, migrate, ship; Phase 3 cutover is a no-op for
   correctly-migrated consumers.
3. This matches the §5.2 atomic-cutover disposition: no
   callable-but-discouraged surface; no zombie code. Same
   discipline at the Phase 1 boundary as at the Phase 3 boundary.

This decision pins the inversion of a recurring discipline
anti-pattern: production-software-discipline defaults
(graceful-degradation, deprecation windows) leak into pre-genesis
contexts when not explicitly inverted. The Phase 0 Mission Audit's
`b1_disposition_settled_delete` + this Phase 1 disposition are
two instances of the same inversion.

### 4.4 `seed_language` field removed; wallet creation does not carry "seed language" concept

The `seed_language` field on `wallet2` (currently
`src/wallet/wallet2.h:1728`) is dropped in Phase 4. BIP39 is
English-wordlist-only at genesis; there is no language concept to
carry. The JSON serialization of `seed_language`
(`wallet2.cpp:4793–4802` write, `:5344–5347` read) is dropped
alongside the field.

Multilingual BIP39 wordlists (Japanese, Spanish, French, etc.,
per BIP39 spec) are a future feature that, if needed, lands via
the Rust-side BIP39 implementation in `shekyl-crypto-pq::bip39`,
not via re-introducing a wallet2 `seed_language` field. The wallet
state structure does not need a multilingual concept; the
seed-presentation layer (GUI) can pick a wordlist at display
time.

### 4.5 `query_key` string-key kept as `"mnemonic"`; routing changes to Rust BIP39

Split from the Gap-1 review: this is two decisions bundled into
one.

**Routing decision (load-bearing): route `query_key("mnemonic")`
to the Rust BIP39 entry.** After Phase 4, the wallet's
"mnemonic"-keyed query returns the BIP39 phrase derived from the
wallet's seed material, not the 25-word Electrum-words encoding.

**String-key decision (UX call): keep the string key as
`"mnemonic"`.** Rationale: "mnemonic" is the universal industry
term for BIP39 phrases. Renaming the key to `"bip39_phrase"`
forces every downstream integrator (shekyl-gui-wallet, future
third-party wallets, future block-explorers) to migrate string
constants without semantic benefit. The phrase *is* a mnemonic;
keeping the key as `"mnemonic"` is the lower-friction choice and
matches industry convention (BIP39 spec itself uses "mnemonic
sentence" throughout).

These two decisions sit at different altitudes — the routing
decision is architecturally load-bearing (changes which code
produces the value); the string-key decision is UX (changes
which string downstream code uses to *request* the value). They
are pinned separately so future audits can re-open one without
re-opening the other.

### 4.6 CryptoNote-25-word format unsupported, period

There is no fallback path. No "if seed has 25 words, try
Electrum-words decoding" branch. The 25-word format is removed
from the codebase entirely; attempting to restore from a 25-word
phrase produces a BIP39 validation error
(`"not a valid BIP39 mnemonic"`).

This is the same discipline as `60-no-monero-legacy.mdc`'s
"deleted, not gated" principle applied to seed format.

### 4.7 Cross-boundary zeroization contract for the BIP39 phrase

The BIP39 phrase is the master secret. Crossing the FFI boundary
in either direction triggers the cross-boundary zeroization
contract:

1. **Originating-scope zeroization.** Rust side produces
   `Zeroizing<[u8; N]>` for entropy and seed bytes (already true
   per `shekyl-crypto-pq::bip39` upstream contract via
   `bip39 = { features = ["zeroize"] }` per Batch α PR 1).
   C++ user-input side uses `epee::wipeable_string` (already the
   pattern for wallet2 password / seed paths).

2. **Transit buffer discipline.** Any intermediate FFI transit
   buffer (the `const uint8_t* words_ptr` parameter on the FFI
   call; any C++-side staging buffer for return values) is
   zeroized after copy. The C++ caller wraps the FFI invocation
   in a scope that wipes its staging buffer on return.

3. **No long-lived aliasing.** Phrase bytes never persist in
   long-lived C++ storage after the FFI call returns. The wallet2
   keyfile-persistence path persists the *derived keys*, not the
   phrase itself. The `query_key("mnemonic")` reply produces the
   phrase from the seed material on demand; no in-memory cache
   of the phrase is maintained.

4. **Test invariant (§7.4).** A memory-residency invariant test
   (modelled on the KEY_ENGINE.md §7.5 audit pattern) runs after
   wallet generation/restore via the new path: scan the C++ heap
   for known phrase bytes after the FFI call returns; assert
   zero matches.

This contract is documented here (not just inline in code
comments) so future audits have a single load-bearing reference
for what the boundary discipline is, and so the test invariant
in §7.4 has a clear specification to verify.

### 4.8 Documented residual: swap and hibernate exposure

The cross-boundary zeroization contract in §4.7 covers
heap-resident bytes and FFI transit buffers. It does **not**
cover two pre-Linux-3.x-era exposure paths that affect every
secret-holding process on commodity operating systems:

1. **Swap-out.** During the phrase's active scope on either
   side of the FFI boundary, memory pressure can cause the OS
   to evict the holding pages to swap. The swap file persists
   the phrase bytes to disk; subsequent reads of `/dev/sda` (or
   the swap device) by an attacker with disk access recover the
   phrase.
2. **Hibernate.** When the host machine hibernates (suspend-to-disk),
   the entire process address space — including
   active secret-bearing pages — is written to the hibernate
   image. Wake-from-hibernate restores the image, but a copy
   persists in the hibernation file.

The standard mitigation is `mlock` (or `shekyl_mlock` per
[`35-secure-memory.mdc:165`](../../.cursor/rules/35-secure-memory.mdc))
on the phrase's holding pages, plus `prctl(PR_SET_DUMPABLE, 0)`
and `madvise(MADV_DONTDUMP)` per the same rule's "OS-level
protection" section. Both mitigations are partial:

- `mlock` prevents swap-out but not hibernate (hibernate
  bypasses `mlock` on most OSes because the entire RAM is
  snapshotted).
- `PR_SET_DUMPABLE` prevents core dumps but not deliberate
  attacker reads of memory via `/proc/<pid>/mem` (root) or
  `ptrace` (CAP_SYS_PTRACE).

**Disposition for V3.0:** The BIP39 phrase is `mlock`'d during
its active scope on both sides of the FFI boundary (Rust side
already does this via `bip39 = { features = ["zeroize"] }`'s
`Zeroizing<>` wrapping plus the `shekyl_mlock` discipline; C++
side wraps the `wipeable_string` in `mlock`'d page allocation
per Rule 35 §"OS-level protection"). Hibernate exposure is
**documented as a known residual**, not enforced in V3.0.

**Rationale for the residual:** mitigating hibernate exposure
requires either (a) OS-level cooperation (a "no-hibernate
process" flag on Linux that does not exist in mainline as of
2026-05-19), (b) zeroing the phrase on every userspace context
switch (prohibitively expensive), or (c) refusing to run on
hibernate-capable systems (rejects every laptop and most
desktops). All three are forward-impractical. The disposition is
to mlock against swap (the routine exposure path) and accept
hibernate as a residual the user takes on when they choose to
hibernate a machine holding secrets.

**Pairing with the wallet master-key residual.** The wallet's
long-term spend key / view key / PQC secret keys have the same
swap-and-hibernate residual. Pinning it for the BIP39 phrase
specifically — rather than implicitly relying on the
master-key residual to also cover the phrase — makes the
discipline visible: every secret-bearing surface in the wallet
inherits the same residual, and every audit-priority risks
review re-asserts the same disposition.

**Reversion criteria (per Rule 21):** This residual is
re-opened if (a) the OS landscape changes such that
mlock-against-hibernate becomes practical (a mainlined Linux
kernel facility, a macOS / Windows equivalent), or (b) Shekyl
ships in a context where hibernate is structurally impossible
(e.g., a dedicated hardware appliance running a custom OS
without suspend support) and the discipline becomes
enforceable, or (c) a user-class emerges that requires the
hibernate residual to be closed (e.g., institutional
cold-storage workflows where hibernate exposure is
unacceptable).

Documentation cross-reference:
[`35-secure-memory.mdc:163–172`](../../.cursor/rules/35-secure-memory.mdc)
("OS-level protection" section) is the canonical rule for the
mitigation discipline; this §4.8 is the audit-of-record for the
BIP39 phrase's specific application of that discipline.

### 4.9 Pinned class-level observation: user-protection defaults in user-absent contexts

The Phase 1 hard-error inversion (§4.3) and the §5.2
atomic-cutover inversion are two instances of a broader class:
defaults inherited from production-software discipline where
there are deployed users to protect. Pre-genesis, with no users,
these defaults invert. The class also includes (non-exhaustive):

- **Backward-compatibility preservation.** Production-software
  default: never break consumers. Pre-genesis inversion: there
  are no consumers; delete-not-gate per
  [`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc).
- **Opt-in migration paths.** Production-software default:
  give users a window to migrate. Pre-genesis inversion: no
  users to give a window to; `rm -rf ~/.shekyl` is the migration
  path per
  [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc).
- **Soft deprecation (`[[deprecated]]` annotations without
  delete dates).** Production-software default: warn early,
  delete eventually. Pre-genesis inversion: if you can't name
  the delete version, you can't deprecate — delete now per Rule
  15.
- **Version-skew tolerance.** Production-software default:
  accept old protocol versions. Pre-genesis inversion: there is
  one version (genesis); per
  [`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc),
  earlier versions are dead code.
- **Graceful degradation under unknown input.** Production-software
  default: accept-and-warn. Pre-genesis inversion: §4.3
  hard-error.
- **Staged rollouts with deprecation windows.** Production-software
  default: ship to a fraction, monitor, expand. Pre-genesis
  inversion: §5.2 atomic-with-justified-exceptions.

The class-level pattern is **"user-protection defaults in
user-absent contexts."** Each instance is a default that
production-software discipline ships pre-loaded; each requires
explicit inversion when the underlying "users to protect"
assumption does not hold. The inversion is not a once-per-pattern
discipline — it is a once-per-design-decision discipline,
because the same default re-enters every design review under a
different guise.

This observation is folded into
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
as a sibling subsection to the existing "cost-benefit-defer-to-later"
anti-pattern, so future PRs have a class-level name to anchor
disciplinary correction. The two PR-4-Phase-0 instances (§4.3,
§5.2) are exemplars; future PRs will surface more, and each
should cite the rule's class-level entry.

---

## 5. Cross-repo coordination

### 5.1 Consumer matrix (post-pre-flight)

| Repo | wallet2_ffi binding state (2026-05-19) | Phase 3 migration party? |
| --- | --- | --- |
| `shekyl-core` | N/A (host repo) | Yes (publishes the FFI deletion PR) |
| `shekyl-gui-wallet` | Active consumer; substantial Electrum-words integration | Yes (publishes a coordinated migration PR) |
| `shekyl-mobile-wallet` | Not yet a consumer | No (picks up post-deletion FFI when it begins binding) |
| `shekyl-web` | Not a consumer | No (picks up post-deletion FFI when it begins binding) |

### 5.2 Cutover default: atomic-with-justified-exceptions

For first-party Shekyl repos at pre-genesis, the default
cross-repo cutover discipline is **atomic** — the shekyl-core
FFI deletion PR and the shekyl-gui-wallet migration PR land as a
coordinated unit. **Staged cutover (with deprecation window)
requires an explicit named third-party dependency justification.**
No such third-party dependency exists for B-1; the atomic default
applies.

Rationale for the default inversion (versus the production-software
"staged with deprecation window" inheritance): per `60-no-monero-legacy.mdc`
and the pre-genesis posture, all consumers are first-party and
under coordinated maintenance. The staged-cutover pattern exists
to protect deployed third-party users; that constraint does not
apply pre-genesis. Staged cutover introduces a callable-but-deprecated
surface that is itself the failure mode `60-no-monero-legacy.mdc`
forbids ("commenting out" / "callable-but-discouraged" code).

The atomic-with-justified-exceptions default is also the
forward-template for future cross-repo deletion work: a future
PR adding a third-party Shekyl consumer (community wallet, block
explorer, etc.) that needs Electrum-words removal could file a
staged cutover with the named third-party dependency as the
justification, and the audit-of-record would accept it. Without
such a dependency, atomic is the default.

### 5.3 Phase 3 cutover mechanism: coordinated dev-tip merge (pre-genesis)

For B-1 specifically (pre-genesis), the cutover mechanism is:

1. shekyl-core PR opens against `dev` with the FFI deletion + RPC deletion + wallet2 internal cleanup.
2. shekyl-gui-wallet migration PR opens against `dev` (in the shekyl-gui-wallet repo) with the bridge / commands / UI migration. PR body cites the shekyl-core PR by URL.
3. Both PRs run their respective CI to green.
4. Same-day merge: both PRs merge into their respective `dev` branches in coordinated sequence (shekyl-core first if shekyl-gui-wallet's CI depends on a tagged shekyl-core artifact; otherwise either order works because shekyl-gui-wallet's `Cargo.toml` pin can be updated to a post-merge `dev` SHA after the shekyl-core merge).
5. The atomic boundary is the *post-merge `dev` tip state* in both repos. There is no signed-tag boundary at this phase because pre-genesis there are no released versions yet.

This is the simpler model for pre-genesis. Post-genesis, the
paired-signed-tag mechanism (next section) is the forward
default.

### 5.4 Phase 3 reversion mechanism: commit-revert in coordinated order

Matching the cutover mechanism: revert is at the commit level on
`dev` in both repos. Ordered:

1. **shekyl-gui-wallet revert** restores the Electrum-words
   consumption pattern in `wallet_bridge.rs` / `commands.rs`.
2. **shekyl-core revert** restores the FFI surface
   (`wallet2_ffi_restore_deterministic_wallet`, `language`
   parameters, `query_key("mnemonic")` dispatch).
3. **Verification** that both repos compile and pass their full
   test suites against the post-revert `dev` tip.

If a revert is needed mid-phase (after only one repo's PR has
merged), the order is simpler: revert the merged PR and re-open
the partner PR's review.

### 5.5 Post-genesis forward template: paired signed annotated tags

This is documented for completeness so future audits don't read
the §5.3 coordinated-dev-tip mechanism as a permanent precedent.

Post-genesis (V3.0 release and beyond), cross-repo coordinated
deletions follow the paired-signed-tag pattern:

1. shekyl-core PR merges to `dev`; shekyl-core release PR merges
   `dev → main` per
   [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc).
2. shekyl-core signed annotated tag `vX.Y` placed on the
   resulting merge commit (Foundation YubiKey).
3. shekyl-gui-wallet `Cargo.toml` / build pin updated to
   `refs/tags/vX.Y` of shekyl-core.
4. shekyl-gui-wallet release PR + signed tag `vX.Y` (sibling
   tag, Foundation YubiKey).
5. Both tags announced together post-CI-green-on-both.

The reversion mechanism in this post-genesis future-default is
**untag both releases and re-pin shekyl-gui-wallet to the prior
shekyl-core tag.** The merged `dev` tip is not reverted; only
the release boundary moves backward. Future audits / users
consuming `refs/tags/vX.Y` see the prior tag's tree.

B-1 Phase 3 does not use this mechanism because pre-genesis
there is no `vX.Y` baseline; the genesis tag is the first
release.

---

## 6. Alternatives considered

### 6.1 Keep Electrum-words for backward compat (REJECTED)

Rationale: per §1.1, no Shekyl-side installed base exists
pre-genesis. "Backward compat" with whom? The only consumers
that could exist are first-party Shekyl repos, which are all
under coordinated maintenance per §3.2. There is no third-party
Electrum-words-relying caller to be backward-compatible with.

The version of this argument that says "but post-genesis a user
might try to restore from a 25-word Electrum seed" is rejected
by §4.6: post-genesis, attempting to restore from a 25-word
phrase produces a BIP39 validation error. This is the intended
behaviour, not a regression.

### 6.2 Partial deletion (audit-strict three-site scope) (REJECTED)

The Phase 0 Mission Audit's initial framing of "three call
sites" — `wallet2.cpp:1374` internal, `wallet2_ffi.cpp:648`
`query_key("mnemonic")` dispatch, `wallet_rpc_server.cpp:2214`
RPC handler — was a simplification that did not survive contact
with the actual deletion surface (per §2's inventory). Deleting
only the three audit-identified sites would leave:

- `is_deterministic` / `get_seed` function bodies as
  dead-but-callable code (no in-tree callers, but binary symbols
  remain).
- `wallet2_ffi_restore_deterministic_wallet` still wired through
  to `crypto::ElectrumWords::words_to_bytes`.
- `src/mnemonics/` directory still compiled, linked, and shipped
  in the wallet libraries.
- `seed_language` field still in `wallet2` state and JSON
  ser/de.

The result is a half-deleted subsystem that is exactly the
"commented out / callable-but-discouraged" residue
`60-no-monero-legacy.mdc` forbids. The architecturally-integral
answer is full subsystem deletion per the inventory in §2.

### 6.3 Defer to V3.1+ (REJECTED)

The cost-benefit calculus for "defer the Electrum-words deletion
to a V3.1 post-launch cleanup" is dominated by the
pre-genesis-discount asymmetry (per
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)):

- Pre-genesis: deletion cost ≈ 5 PRs × ~half-day each = ~3 days
  developer time. No migration tooling required. No data-format
  detection. No user-facing notice.
- Post-genesis: deletion cost includes data-migration tooling for
  any user that opened a Shekyl wallet before V3.1, plus a
  deprecation-window posture for several releases. Migration
  tooling runs forever to handle state that exists for a finite
  period (per `15-deletion-and-debt.mdc`'s "migration code is a
  permanent attack surface for a one-time problem").

This is the `cost-benefit-defer-to-later` anti-pattern named
in
[`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc):
the deferred-benefit calculation systematically underweights
the value of pre-genesis structural cleanup. The
architecturally-integral disposition is to land the deletion
now.

### 6.4 BIP39 ↔ Electrum-words bridge function (REJECTED)

Adding a `bip39_phrase_to_electrum_words` (or the inverse)
function to the codebase as a migration aide is rejected as
load-bearing migration code per §1.1. There is no pre-genesis
installed base to migrate. Adding the bridge function creates a
new attack surface for a non-existent problem.

The version of this argument that says "post-genesis a user
might want to display their seed in both formats for redundant
backup" is rejected by §4.6: there is one canonical seed format
post-genesis (BIP39); the redundant-backup pattern is multiple
copies of the same format, not multiple formats.

### 6.5 Reversion clauses per Rule 21

Per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc),
the rejected alternatives in §6.1–6.4 are not closed forever;
they are closed under named criteria, and a future PR can
re-open the disposition by surfacing those criteria as met.
Reversion criteria:

| Disposition | Reverts on |
| --- | --- |
| §4.1 BIP39-only from genesis | A pre-genesis discovery that BIP39 has a security-load-bearing vulnerability that no other industry mnemonic standard shares (extremely unlikely; BIP39 is the broadly-deployed standard). |
| §4.2 wallet2::generate() retains orchestrator role | The B-3 architectural workstream lands and the (a) stop-gap shape becomes the dead intermediate. Note: this is a *forward* progression, not a reversion of the §4.2 disposition. |
| §4.3 Phase 1 hard-error on non-empty `language` | Never — this disposition is the locked discipline; hardening it further (e.g., compile-time deletion of the parameter at Phase 1 rather than runtime hard-error) is a forward progression that does not violate §4.3. |
| §4.4 `seed_language` field removed | Multilingual BIP39 wordlist support becomes a roadmap item AND the implementation requires wallet2-side state. The reversion path is: re-introduce the field as `bip39_wordlist_language: String` (not `seed_language`); never as the Electrum-words-coupled field this disposition removes. |
| §4.5 `query_key` string-key kept as `"mnemonic"` | An external integrator surfaces a named conflict between `"mnemonic"` and another industry usage that produces ambiguity (extremely unlikely; "mnemonic" is the universal term). |
| §4.6 CryptoNote-25-word format unsupported | Never — see §6.1. |
| §4.7 Cross-boundary zeroization contract | The audit invariant in §7.4 surfaces a residency leak. The reversion path tightens the contract, not loosens it. |
| §4.8 Swap/hibernate residual | Per §4.8 explicit reversion criteria: (a) OS-level no-hibernate facility lands; (b) Shekyl ships in a hibernate-impossible context; (c) a user-class emerges requiring the residual to be closed. Reversion path is **closing** the residual, not loosening it. |
| §4.9 Pinned class-level observation | Never — naming the class-level pattern is itself the disposition. Refinements to the named class (additional instance categories surfaced by future PRs) extend the rule's enumeration; they do not reverse §4.9. |
| §5.2 atomic cutover default | A named third-party consumer of `wallet2_ffi` surfaces during B-1 flight. The reversion path is the staged-cutover disposition with the third-party named explicitly. |

---

## 7. Test surface and verification invariants

### 7.1 nm symbol-isolation invariants

After Phase 5 lands, the following symbols MUST NOT appear in
`nm shekyld` or `nm libwallet2_api.so` output (or equivalents):

```text
crypto::ElectrumWords::words_to_bytes
crypto::ElectrumWords::bytes_to_words
crypto::ElectrumWords::is_valid_language
crypto::ElectrumWords::get_language_list
crypto::ElectrumWords::get_is_old_style_seed
crypto::ElectrumWords::old_language_name
tools::wallet2::is_deterministic
tools::wallet2::get_seed
tools::wallet2::get_seed_language
tools::wallet2::set_seed_language
wallet2_ffi_restore_deterministic_wallet
```

A CI check (`tests/symbol_isolation/electrum_words_removed.sh`)
runs `nm | grep -E '<pattern>'` against the build artifacts and
fails the build if any symbol matches. Pattern matches the LWMA-1
Phase 4 §7.1 precedent.

### 7.2 git grep no-orphans invariants

After Phase 5 lands, the following identifiers MUST NOT appear in
the source tree (excluding `docs/CHANGELOG.md` historical entries
and `docs/design/ELECTRUM_WORDS_REMOVAL*.md` which retain
references for audit purposes):

```text
ElectrumWords
electrum-words.h
seed_language
is_deterministic
get_seed_language
set_seed_language
mnemonics/english.h
mnemonics/japanese.h
(etc., all 14 language headers)
restore_deterministic_wallet
COMMAND_RPC_GET_LANGUAGES
COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET
```

A CI check (`tests/grep_invariants/electrum_words_no_orphans.sh`)
runs `git grep -E '<pattern>'` against the tree and fails the
build if any non-allowlisted match exists. Pattern matches the
LWMA-1 Phase 4 no-orphaned-magic-numbers invariant.

### 7.3 BIP39 round-trip tests

Tests added in Phase 1 (alongside the wallet2 internal rewire)
verify the BIP39 path produces correct wallets:

- Generate a wallet via the new `wallet2::generate()` path; verify
  the wallet's primary address matches the BIP39-derived address
  for the same entropy + passphrase.
- Restore a wallet from a BIP39 phrase; verify the recovered
  wallet's primary address matches.
- Round-trip: generate → query seed via `query_key("mnemonic")`
  → restore from that phrase → assert wallets are identical.

These tests live in `tests/unit_tests/wallet_bip39.cpp` (a new
test file added in Phase 1).

### 7.4 Memory-residency invariant test (per §4.7)

A test added in Phase 1 verifies the cross-boundary zeroization
contract:

1. Generate a wallet with a known BIP39 entropy.
2. After the FFI call returns, scan the C++ heap (process memory
   range, or instrumented allocator hook) for the known phrase
   bytes.
3. Assert zero matches.

This test lives in `tests/unit_tests/wallet_bip39_residency.cpp`.
The test pattern follows the
[KEY_ENGINE design doc §7.5 audit pattern](../design/STAGE_1_PR_3_KEY_ENGINE.md);
if that doc's audit pattern is updated, this test is updated to
match.

### 7.5 Test fixtures touched, zero-production-keyfile confirmation

Test fixtures that exercise Electrum-words paths today:

- `tests/unit_tests/mnemonics.cpp` — deleted entirely in Phase 5.
- `tests/unit_tests/serialization.cpp` (if it deserializes legacy
  wallet JSON with `seed_language`) — Phase 4 sweep removes the
  `seed_language` field from any test fixtures.
- `tests/functional_tests/wallet.py` (Python integration tests)
  — Phase 2 sweep removes `restore_deterministic_wallet` /
  `get_languages` RPC calls; Phase 3 sweep removes any
  `set_language` integration.

**Pre-genesis posture confirmation:** there are zero production
Shekyl wallet keyfiles in existence (the project has not yet
released V3.0). Any test fixtures are project-internal artifacts
under coordinated maintenance. Deletion of the `seed_language`
field does not require production-data migration tooling.

If a future contributor discovers a production keyfile (e.g., a
test wallet committed to a branch that gets restored later), the
keyfile is regenerated from its source BIP39 phrase per the
project's pre-genesis migration discipline (`rm -rf` and re-sync
per `15-deletion-and-debt.mdc`).

---

## 8. References

### Design-doc precedents

- [`DAA_LWMA1.md`](./DAA_LWMA1.md) — LWMA-1 difficulty
  adjustment substrate doc. Style and section-decomposition
  template.
- [`DAA_LWMA1_PLAN.md`](./DAA_LWMA1_PLAN.md) — LWMA-1 multi-phase
  plan template; companion to this doc's
  [`ELECTRUM_WORDS_REMOVAL_PLAN.md`](./ELECTRUM_WORDS_REMOVAL_PLAN.md).
- [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) — RandomX v2
  substrate doc; "no version dispatch" disposition template.

### Phase 0 Mission Audit substrate

- `docs/FOLLOWUPS.md` — Phase 0 Mission Audit findings index;
  B-1 entry.
- Audit substrate pins (in chat transcript / audit notes):
  `b1_disposition_settled_delete`, `b1_vestigial_verification`
  (now closed by this PR), `per_surface_walk_b1_b2_c1_c3`.

### BIP39 specification

- BIP-0039 — Mnemonic code for generating deterministic keys.
  Implementation in `rust/shekyl-crypto-pq/src/bip39.rs`
  (already a workspace dependency with `zeroize` feature enabled
  per Batch α PR 1).
- The BIP39 wordlist file (English) lives at the
  `bip39 = { version = "...", features = ["zeroize"] }` crate's
  vendored wordlist.

### Rules

- [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc) —
  priority hierarchy. B-1 is a priority-3 commitment-3 work
  (the system must outlast the team; pre-genesis cleanup serves
  unknown future maintainers).
- [`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc) —
  spec-first, code-second. This doc is the spec.
- [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) —
  short-lived branches; the five-PR decomposition fits.
- [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc) —
  pre-genesis-discount; migration-code anti-pattern; "while
  we're here" discipline.
- [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc) —
  inheriting code vs. inheriting architecture; the
  cost-benefit-defer-to-later anti-pattern.
- [`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc) —
  Rust if touches a secret. Phase 0 design rounds discipline.
- [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc) —
  reversion criteria per disposition (§6.5).
- [`35-secure-memory.mdc`](../../.cursor/rules/35-secure-memory.mdc) —
  wipe-on-drop discipline; substrate for §4.7 zeroization
  contract.
- [`36-secret-locality.mdc`](../../.cursor/rules/36-secret-locality.mdc) —
  Rust owns secrets at the C++/Rust boundary; substrate for
  §4.2 disposition (a).
- [`60-no-monero-legacy.mdc`](../../.cursor/rules/60-no-monero-legacy.mdc) —
  "deleted, not gated" principle; substrate for §4.1 and §4.6.
- [`91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc) —
  Phase 6 docs-update obligation; CHANGELOG entry.

### Cross-repo references

- `shekyl-gui-wallet` — `src-tauri/src/wallet_bridge.rs`,
  `src-tauri/src/commands.rs` (Phase 3 migration sites).
- `shekyl-core` — `rust/shekyl-ffi/src/account_ffi.rs`,
  `src/shekyl/shekyl_ffi.h` (BIP39 bridge; already in place).
- `rust/shekyl-crypto-pq/src/bip39.rs` — Rust BIP39
  implementation (already used in production).

---

*End of substrate doc. Implementation phasing in
[`ELECTRUM_WORDS_REMOVAL_PLAN.md`](./ELECTRUM_WORDS_REMOVAL_PLAN.md).*
