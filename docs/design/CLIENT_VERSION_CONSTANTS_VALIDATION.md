# VC — Client-side version and constants validation

**Status:** OPEN — design round 1. Dispositions `VC-D1`…`VC-D12` are
**proposed**, not ruled. **`VC-1` is built in the PR that lands this
document** (steering ruling, 2026-09-05: no wire change, no C++, so it clears
the alpha.8 slowdown); `VC-2`…`VC-4` are not started. **No wire change is
authorised while this banner reads round 1** (the design category is exempt
from the slowdown; a `get_version` field is not). Every `file:line` below was
read at `dev` = `2dba46537` (PR #619, RK-5b merge); the anchor for `VC-1`'s
landing is `e54e5b983`.
**Identifier family:** `VC-` (version and constants validation), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 in the commit that
lands this document (rule 94). `VC-D*` are dispositions of this round;
`VC-1`…`VC-4` are the implementation slices §4 names. Neighbours checked:
`CV-` (cover traffic) is taken and is a different family; `VC-`, `CDG-` and
`HS-` were free at the anchor.
**Parent:** [`DAEMON_RPC_KV_CUTOVER.md`](DAEMON_RPC_KV_CUTOVER.md) §7, the
2026-09-04 rows that found both facts below and named this round without
building it.
**Process rule:** [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
is invoked: multi-round, crosses the FFI boundary (`VC-2` widens the chain
facts POD) and the wire (`VC-2` bumps `CORE_RPC_VERSION`), and touches
consensus-adjacent constants. `VC-2` gets a pre-flight pass before code.
**Decision authority:** Rick. §6 lists the rulings this round needs.

**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
privacy is the product, and a wallet that scans a daemon on a different
chain or a different network shows its owner a balance that is not theirs;
the system must outlast the team, and a published fact nobody reads is
maintenance with no consumer. This round trades nothing in security: the
check refuses, and refusing is the safe direction on every arm (§3.6).

---

## 0. Problem statement, verified at source

Two published facts on the daemon's RPC surface have no consumer. Both were
found during RK-5b; both were re-swept for this document rather than
inherited, because a negative claim inherits well and verifies badly.

### 0.1 `CORE_RPC_VERSION` is read by nobody

The unfiltered sweep, run at the anchor — **not** narrowed by expected
phrasing, per the 2026-09-04 lesson that a filtered sweep reports clean for
exactly the cases it was written not to match:

```
grep -rn "CORE_RPC_VERSION" rust/ src/ tests/ utils/ \
  --include=*.rs --include=*.cpp --include=*.h --include=*.py | grep -v target/
```

31 hits, every one read:

| Hits | What they are |
| --- | --- |
| 1 | The producer: `rust/shekyl-daemon-rpc/src/methods.rs:129` fills `GetVersionResponse.version`. |
| 2 | The producer's own unit test (`methods.rs:1852`, `:1873`) asserts the reply carries the constant. |
| 4 | The constant's definition: `rust/shekyl-rpc-types/src/chain.rs:44`, `:80`, `:81`, `:82` (major, minor, the packing formula). |
| 4 | The constant's pins: `chain.rs:383–386` (packed value, packing expression, major, minor — the 2026-09-04 merge-safety fix). |
| 11 | The oracle-vector parity and chain-delta tests in `rust/shekyl-rpc-types/tests/rpc_parity.rs`. |
| 2 | The re-export, `rust/shekyl-rpc-types/src/lib.rs:82–83`. |
| 7 | Comments and doc comments (`chain.rs:41`, `:45`, `:338`, `:367`; `headers.rs:16`; `src/rpc/core_rpc_server_commands_defs.h:84`, `:89`). |

**Zero hits compare the constant to a value that came off the wire.** Not
`shekyl-daemon-rpc/src/console/` (the `shekyld <command>` arm), not
`shekyl-rpc-client`, not `shekyl-engine-core`'s daemon client, not
`shekyl-cli`'s. The `version` field is produced, versioned, pinned, chained
across four oracle vectors and delta-tested at every link — and changes
nobody's behaviour. This is the *correct mechanism with no consumer* class
the parent's §7 named on 2026-09-04.

### 0.2 `get_info.nettype` is read by nobody either — and a plan lock says it is

The C++ `on_get_info` fills `nettype` as one of `"mainnet"`, `"testnet"`,
`"stagenet"`, `"fakechain"` (`src/rpc/core_rpc_server.cpp:237`). No Rust
client reads it: `grep -rn nettype rust/shekyl-engine-core/src
rust/shekyl-wallet-rpc/src rust/shekyl-cli/src rust/shekyl-daemon-rpc/src/console`
returns nothing outside tests. `rust/shekyl-rpc-types` has no `nettype`
anywhere — `get_info` is still a bridged C++ leg (RK-5c's).

That would be a second instance of §0.1, except that this one was
**required**. [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) :216,
cross-cutting lock 5:

> `Wallet::open` requires a `DaemonRpcClient` whose declared network
> matches; mismatch is `OpenError::NetworkMismatch`, never a warning. The
> daemon URL's network is **verified via `get_info` before any wallet
> operation** — defends against DNS hijack pointing a testnet wallet at a
> mainnet daemon.

What landed is half of that. `OpenError::NetworkMismatch`
(`rust/shekyl-engine-core/src/engine/error/lifecycle.rs:52`) is raised from
`lifecycle/support.rs:53` by translating `WalletFileError::NetworkMismatch` —
the **wallet file's** declared network against the caller's `expected`
parameter. The daemon is never asked — the variant's own shape,
`{ wallet, expected }`, has no field for a daemon-reported value, so the type
could not implement the lock even if a call site wanted to. And two
docstrings say the opposite of what the code does. `engine/daemon.rs:169`:

> Daemon network verification is performed by `Engine::open_*` against the
> on-disk wallet file's network declaration.

— literally true about what it does, while its subject says "daemon network
verification"; a reader takes the subject. And `engine/error/mod.rs:41`,
under "variant names locked in by the plan":

> `OpenError::NetworkMismatch` — wallet file says network N, daemon client
> says network M.

Both are *prose claims asserted rather than tested* — the second of the
three defect shapes RK-5b's six review rounds catalogued — and both have been
standing since Phase 1. `VC-4` corrects both in the same PR as the check;
prose that is load-bearing-false does not get a follow-up.

The regtest end-to-end suite (`engine/regtest_e2e.rs`) opens `Network::Mainnet` wallets against a
`shekyld --regtest` daemon that reports `"fakechain"`, and passes, which is
the proof: the check does not exist, so nothing has ever had to accommodate
it (§3.6.4 is where that accommodation is designed).

### 0.3 The one client-side constants check that exists is narrow by design

`rust/shekyl-daemon-rpc/src/console/info.rs:117` (`daa_target_seconds`)
compares `/get_info`'s `target` against the build's own
`crate::consensus::DAA_TARGET_SECONDS` and *warns*, rendering from the
build's value. RK-5b wrote it that narrow on purpose and said so in the
function's doc comment: "the general instrument … is a separate round; it is
not built here". This is that round. `VC-D11` rules what happens to the
narrow check when the general one lands.

### 0.4 Who acts differently because of a published fact

That is the question this round exists to answer, and today the answer is
"nobody". The table is what that leaves open, per axis of difference between
a client's build and the daemon it dials:

| Client and daemon differ in | What happens today | Why it matters |
| --- | --- | --- |
| **Wire shape** (`CORE_RPC_VERSION`) | A renamed or removed field fails `deny_unknown_fields` deserialisation at the first method that reads it, with a message naming a field, not a version. An *omitted* field with `#[serde(default)]` becomes its zero **silently** — the open FOLLOWUPS item "`#[serde(default)]` still lets an omitted daemon field become its zero value", 27 fields. | A late, per-method, badly-worded failure at best; a confident zero at worst. |
| **Consensus rules** (`config/consensus_constants.json`) with the same wire shape | Nothing. Every method parses. The console prints statistics from a different chain; the wallet scans and shows a balance computed under different rules. Only `T` gets a warning (§0.3). | A daemon rebuilt from a different constants file *is a different chain* wearing the same RPC contract. |
| **Network** (`mainnet` / `testnet` / `stagenet` / `fakechain`) | Nothing. A testnet wallet pointed at a mainnet daemon — the lock-5 DNS-hijack case, verbatim — scans mainnet. | The plan ruled this a typed refusal in Phase 1; it never landed. |

Three axes, three different failures, three different messages an operator
needs. That is why §2 does not collapse them into one "handshake".

**And the wrong-chain daemon is undefended twice over, today.** The lock-5
attack — a wallet pointed at a daemon on a different chain — has no network
check (§0.2) *and* no genesis check: no Rust pin of a genesis block hash
exists and no client compares block 0's hash to anything (found 2026-09-05
while grounding `VC-D12`; §2's genesis row). Three stated commitments were
chased on this day and all three lacked an enforcing site — the plan's
"verified via `get_info`", this document's own first draft's "committed to
by the genesis block hash", and, in another lane, `GENESIS_TX_WIRE_FORMAT`'s
"consensus parses `32·n_outputs`". The identity tuple is the enforcing site
for the first two.

---

## 1. Threat model — what this check is, and what it is not

**T, named:** a client dialing a daemon that is *honestly different* from the
one the client was built for. Instances: a stale binary on one side after a
rebuild; an operator's `--daemon-address` pointing at the wrong node; a DNS
answer that moved (lock 5's case); a daemon rebuilt from an edited
`config/consensus_constants.json`; a `--testnet` daemon behind a mainnet URL.
**Channel:** the RPC reply itself. The daemon states its version, rules
digest and network; the client compares each to its own compiled value.

**What this is not.** It is not authentication. A daemon that *wants* to lie
reports whatever the client expects — the digest is a label the daemon
attaches to itself, not a proof of the rules it runs. A mismatch is proof of
difference; a match is evidence, not proof, of sameness. Trust in the peer
and in the path is the transport posture's job
([`RT-`](IMPLEMENTATION_INDEX.md) family; every RPC leg is operator-to-
operator, the adversary is the network path). This round adds nothing to
that and takes nothing from it — it makes the *honest* mismatch, which is by
far the common case, fail early, loudly and by name instead of late, quietly
and by symptom.

**Why refusing is safe on every arm (§3.6).** The client's alternative to
refusing is to proceed against a daemon it has just proved is different. On
the rules axis that means rendering or scanning a different chain; on the
network axis it means the lock-5 case; on the wire axis it means the
`#[serde(default)]` zero. There is no arm where proceeding is better than
stopping, so there is no arm that needs a "warn and continue" mode — and a
mode that exists gets used ([`21-reversion-clause-discipline`](../../.cursor/rules/21-reversion-clause-discipline.mdc):
optionality without a concrete need is debt).

---

## 2. The identity tuple

A client establishes, once per connection, that the daemon it dialed is the
daemon it was built for, on independent axes (three at the round's opening,
four after `VC-D12`):

| Axis | Client's value | Daemon's value | Mismatch means |
| --- | --- | --- | --- |
| **Wire** | compiled `CORE_RPC_VERSION` | `get_version.version` | the two binaries do not share an RPC contract; every reply is suspect |
| **Rules** | compiled `CONSENSUS_CONSTANTS_DIGEST` (§3.3) | `get_version.consensus_constants_digest` (new, `VC-D5`) | the two binaries were built from different consensus constants; this is a different chain |
| **Network** | the wallet's `Network` / the console's caller | `get_version.nettype` (new, `VC-D5`) | same rules, different instance of them |
| **Genesis** (`VC-D12`, added 2026-09-05) | a per-network pinned genesis block hash, new in Rust | `on_get_block_hash([0])` — served natively since RK-2, **no wire change** | the daemon's chain does not start where this build's does: a different chain, whatever else agrees |

The genesis axis was added when `VC-D12`'s first draft excluded the
`genesis_recipients.*.json` files from the digest on the ground that "the
genesis block hash already commits to them" — and the steering lane checked
whether anything compares that hash. Nothing does: no Rust pin of a genesis
hash exists and no client reads block 0's hash. The daemon pins
`GENESIS_TX` / `GENESIS_NONCE` per network in `src/cryptonote_config.h:368`
(and `:500`, `:511`); the client side has never held the answer. So the
axis joins the tuple (`VC-4` builds it over the existing method) rather than
serving as an excuse. Genesis does not replace network: `FAKECHAIN` takes
mainnet's configuration (`cryptonote_config.h:562`), so a regtest daemon
shares mainnet's genesis and only `nettype` tells them apart; and `nettype`
is the value an operator can read in a refusal. Genesis is the strong check;
network is the discriminator and the message.

Two things follow from `FAKECHAIN` taking mainnet's configuration, stated so
a later reader does not file either as a defect. First, it is rule 71
([`71-network-uniformity`](../../.cursor/rules/71-network-uniformity.mdc))
working exactly as written: the network selects *data* — `FAKECHAIN` selects
mainnet's constants, `GENESIS_TX` and `GENESIS_NONCE` included — and no
control flow diverges on the consensus surface. Second, and this is why the
tuple has several axes rather than one strong one: **the genesis axis has a
structural blind spot exactly where regtest lives, and only the network axis
sees there.** The axes do not merely add confidence to one another; they
cover different failure sets. Wire skew is invisible to every axis but the
first; a rebuilt constants file is invisible to every axis but the second; a
regtest daemon behind a mainnet URL is invisible to the genesis axis and
caught by the third; a daemon on a different chain with the same constants
and network is caught only by the fourth. That coverage difference is the
justification for the tuple's shape — not "defence in depth", which is what
one writes when the difference cannot be named.

The axes are orthogonal and are kept that way in the refusal: the operator
reads *which* axis failed and what each side's value was. "Wrong daemon" is
not an error message; "this daemon runs testnet, this wallet is mainnet" is.

Rules and network are both needed for chain identity. The constants file has
**no per-network data** — one JSON generates every network's constants — so
the digest is identical across mainnet, testnet and stagenet. The parent's §7
sketch called the digest "stronger than a network-ID byte"; the precise
statement is that it is *orthogonal* to one. The digest says "same rules";
the network says "same instance"; a chain is both.

---

## 3. Dispositions

Each is proposed. Rick rules; the round closes when §6 is empty.

### 3.1 `VC-D1` — the wire handshake: strict equality, and it is forced, not chosen

**Proposed:** a client refuses a daemon whose `get_version.version` differs
from its compiled `CORE_RPC_VERSION` in either component, and its message
names which side is older (`daemon 3.27 < client 3.28: the daemon is the
older build` and the converse).

**Why strict and not a compatibility window.** The wire is *already* exact.
Every reply type in `shekyl-rpc-types` carries `#[serde(deny_unknown_fields)]`
(RK-4c's ruling), so a client tolerating a newer daemon's minor bump would
still fail to parse the field that bump added. A window would be a promise
the types cannot keep. Pre-genesis there is also no external consumer to
promise anything to (`RK-D8`). Strict equality is the only policy consistent
with the types as they stand; choosing anything else here would be choosing
it for the types too, which is not this round's to do.

**Reopening criterion:** a post-genesis compatibility window is wanted. That
round must rule `deny_unknown_fields` and the version policy *together*, and
must first close the `#[serde(default)]` FOLLOWUPS item, because a window
across an omitted field is a window across a silent zero.

### 3.2 `VC-D2` — the rules digest: subject is the whole file, not a list

**Proposed:** a digest over the canonical form (§3.3) of
`config/consensus_constants.json`, computed at build time, exposed by the
daemon, compared by the client.

**Rejected alternative A — a per-constant comparison** (`target`, then
`daa_window_n`, then …). Its subject is whatever someone listed. A constant
added next year is uncovered until someone remembers; a constant removed
leaves a comparison of nothing against nothing. The RK-5b lesson (rule 47,
[`47-gate-subject-assertion`](../../.cursor/rules/47-gate-subject-assertion.mdc))
is that a check's subject can silently empty; the digest's subject is the
file and cannot.

**Rejected alternative B — a hash of the file's raw bytes.** Its subject is
too large: a comment edit, a whitespace change or a CRLF introduced by an
editor moves the digest and every client refuses every daemon over a change
to nothing. The 2026-09-05 CRLF row in the parent's §7 is the cautionary
instance. The canonical form exists to make the digest's subject exactly the
constants.

**The argument for the digest, stated once.** It is derive-don't-hardcode
applied to the check itself: the check is derived from the authority rather
than from a hand-maintained enumeration of it.

### 3.3 `VC-D3` — canonicalisation, pinned

Both sides must hash identical bytes or the digest is a false-alarm
generator. The rules, in full:

1. Parse `config/consensus_constants.json` as JSON. Parse failure fails the
   build.
2. Drop every key whose name begins with `_`. These are the file's prose
   (`_comment`, `_comment_daa`, …: 9 of 31 keys at the anchor).
3. Every remaining value **must be a JSON integer**. At the anchor all 22
   are. A string, boolean, float, array, object or null under a
   non-underscore key **fails the build** with the key named. This is
   enforced rather than assumed: the simplicity of the form below depends
   on it, and the generator is where a future non-integer constant is
   caught and this section is reopened.
4. Sort the remaining keys **bytewise ascending** (not locale, not
   case-insensitive). Key names are ASCII `[a-z0-9_]` at the anchor; a
   non-ASCII key is not forbidden but is sorted by its UTF-8 bytes.
5. Emit, as UTF-8:
   - one header line: `shekyl-consensus-constants-canonical-v1` followed by
     LF. This is the domain tag ([`30-cryptography`](../../.cursor/rules/30-cryptography.mdc))
     and the version of the canonical form; changing any rule in this list
     bumps `v1`.
   - then, per key in sorted order: the key, one ASCII space, the value as
     a **decimal integer with no sign, no leading zeros and no separators**,
     LF. Values are non-negative by construction (the C++ generator already
     range-checks every key to `u8` or `u64`); a negative integer fails the
     build.
6. `CONSENSUS_CONSTANTS_DIGEST` = SHA-256 over those bytes, rendered as 64
   lowercase hexadecimal characters.

Why every choice is the boring one: a line-per-key text form has no
serializer-specific behaviour to disagree about — no float formatting, no
string escaping, no key-quoting, no trailing-comma rules — so a Python
generator and a Rust `build.rs` agree by construction, and the form is
checkable by eye. SHA-256 because `sha2` is already a workspace dependency
and because this is a **label, not a protocol hash**: it authenticates
nothing (§1), so the choice of function carries no security weight and the
domain tag is hygiene, not a separation requirement.

**Two pins land with the computation (`VC-1`):**

- a **canonical-form KAT**: a fixed synthetic JSON (with comment keys,
  unsorted keys, values across the `u8`/`u64` range) and its expected
  canonical bytes and digest, so the *rules* are pinned independently of
  the live file;
- a **live-file sentinel**: `const _: () = assert!(CONSENSUS_CONSTANTS_DIGEST
  == "…")` in the style of `shekyl-daemon-rpc/src/lib.rs`'s Decision-14
  sentinels, so a change to the JSON is a reviewed change to a Rust source
  line rather than a silent move of every client's refusal. This is the
  existing convention for exactly this file, extended to the whole of it.

### 3.4 `VC-D4` — one computation, in `shekyl-rpc-types`

The digest must exist in the daemon (to publish) and in every client (to
compare). Where it is computed decides how many copies exist.

| Option | Copies | Verdict |
| --- | --- | --- |
| (a) each consumer's `build.rs` (`shekyl-daemon-rpc`, `shekyl-engine-core`, …) computes it | 2 today, growing | **Rejected.** Three-local-copies-one-wrong is the class this workspace has already paid for; the canonicalisation rules would live in N places. |
| (b) a shared `[build-dependencies]` crate holding the canonicaliser | 1 implementation, N invocations | Workable, but adds a crate whose only job is to be invoked from build scripts. |
| (c) **`shekyl-rpc-types/build.rs`** computes it once and emits `pub const CONSENSUS_CONSTANTS_DIGEST: &str` next to `CORE_RPC_VERSION` | 1 | **Proposed.** Every RPC party — `shekyl-daemon-rpc`, `shekyl-engine-core`, `shekyl-rpc-client` — already depends on this crate; the digest is a wire-contract fact and sits beside the other one. The daemon reads the constant to fill the reply; the client reads the same constant to compare. |

Cost of (c): `shekyl-rpc-types` gains `[build-dependencies] serde_json, sha2`
(both workspace pins) and a `build.rs` that walks to `config/` exactly as
the seven existing generators do. It gains **no** runtime dependency and no
new production surface beyond one `&str`.

**`cmake/generate_consensus_constants.py` does not compute the digest**
(`VC-D9`). Nothing in C++ consumes it: `get_version` is served natively by
Rust since RK-1, and the console's both arms render in Rust. A C++ copy
would be a third implementation of §3.3 with no reader.

### 3.5 `VC-D5` — exposure: `get_version` grows two fields, and the version moves

**Proposed:** `GetVersionResponse` gains

```
consensus_constants_digest: String   // 64 lowercase hex chars, §3.3
nettype: DaemonNetwork               // "mainnet" | "testnet" | "stagenet" | "fakechain"
```

and `CORE_RPC_VERSION` takes the next minor. **At the anchor that is 3.28.
Read `dev` at the moment `VC-2` is written, not at the moment it branched** —
3.26 was claimed by two branches on one day and git merged the line clean.
The whole-chain delta test now catches a taken number, but only at merge.

**Why `get_version` and not `get_info`.** `get_version` is the method whose
question is "what am I talking to"; the handshake is that question with two
more parts. It is served natively, has a typed reply and an oracle chain, and
is not about to change for other reasons. `get_info` carries `nettype`
already but is a bridged C++ leg that RK-5c retires and redesigns, has no
Rust reply type yet, and carries ~40 fields the handshake does not want. A
two-method handshake (`get_version` for wire and rules, `get_info` for
network) would need no new `nettype` field but would tie the identity check
to a leg in flight and read its three facts from two replies. One reply, one
chain state, one oracle vector is the property worth paying one duplicated
field for; `get_info.nettype` becomes RK-5c's to keep or retire (RK-W's wire
cleanup is where duplicates die).

**The FFI cost, named (rule 40).** `shekyl-daemon-rpc/src/chain_facts.rs`
has no network field; the chain-tip POD gains one `u8` (`nettype`, C++
`cryptonote::network_type` mapped at the export) and the C export fills it.
One byte, one field, both sides of the boundary in the same slice, ABI pin
by offset per the existing convention.

**`DaemonNetwork` is a wire-side type**, in `shekyl-rpc-types`, with four
variants including `Fakechain`, deserialised from the daemon's string with
unknown strings refused. It is **not** `shekyl_address::Network`, which
stays three-variant: adding `Fakechain` there is the workspace-wide change
(`V3_WALLET_DECISION_LOG.md` :1397 — HRP tables, `NetworkSafetyConstants`,
`DerivationNetwork`, region-1 byte) that Phase 1 deferred, and this round
does not reopen it. The comparison in §3.6.4 maps between the two.

**The oracle chain.** `rpc_parity.rs`'s
`the_get_version_chain_differs_by_exactly_the_version_at_every_link`
asserts each consecutive vector pair differs by the version and nothing
else. The `v4 → v5` link will differ by the version **and** the two new
fields, so `VC-2` extends the test to name, per link, the fields that link
may add — in the shape of RK-4c's
`v2_is_v1_minus_exactly_the_two_retired_members`, which did the same for
removals. The invariant stays "exactly the version, plus exactly the named
members"; it does not become "roughly the version".

**Rule 42:** `GetVersionResponse` is a wire type, not a persisted block;
`CORE_RPC_VERSION` is the wire's own version constant and is what moves. No
persisted-schema constant is touched.

### 3.6 `VC-D6` — per-arm mismatch policy

Each arm is a different consumer with a different consequence of proceeding.
Each gets its own justification; none gets a "continue anyway" mode (§1).

#### 3.6.1 Console, live arm (`Source::Live`) — no check, because it cannot fail

`shekyld`'s interactive console renders from the live core in the same
process (`console/mod.rs`, `Source::Live(Arc<CoreRpc>)`). Its compiled
version and digest are the daemon's compiled version and digest by identity
of the binary. A check here compares a value to itself, can never fail, and
would be a check that exists to be seen existing. **The parent's sketch
"local console fatal at startup" is rejected on that ground** — every check
must be able to fail.

#### 3.6.2 Console, remote arm (`Source::Remote`) — refuse to render, except `version`

`shekyld <command>` from a second process posts to an address that may be a
different binary. Before rendering any natively-served command, the console
calls `get_version` and compares all three axes. On mismatch it prints the
axis, both values and (for the wire axis) which side is older, and exits
non-zero without rendering the command. The one exemption is **`version`
itself**: its job is to show the operator what they are talking to, so it
renders both sides and the verdict rather than refusing — it *is* the
handshake, made visible.

Rejected: an override flag to render anyway. A console that renders
statistics from a chain it has just proved is not this build's chain prints
confidently wrong numbers, which is the failure §0.3 was written to avoid.
There is no operator task that needs it that `version` does not serve.

#### 3.6.3 Wallet engine — refuse to open, on every axis

`Engine::open_*` (`engine/lifecycle/open.rs`) performs the handshake against
the supplied daemon client **before any wallet operation** — lock 5's
wording, finally honoured — on all four axes of §2 (the genesis axis via
`on_get_block_hash([0])`, a second call against an existing method), and
refuses with a new typed
`OpenError::DaemonIdentityMismatch { axis, ours, theirs }`. `shekyl-cli` and
`shekyl-wallet-rpc` surface it in operator language per
[`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc):
what is wrong, which side, and the one action that fixes it (point at the
right daemon; update the older side). The existing
`OpenError::NetworkMismatch` keeps its meaning (wallet file vs caller) and
its name; the daemon axis is a different error because it is a different
fact.

**Refusing to read, not only to submit.** The parent's sketch offered
"wallet engine refuse to submit" and the dispatch suggested that refusing to
*read* "may be merely annoying". It is not, twice over:

- on the **rules** axis, reading is scanning a different chain — the balance
  and history shown are computed under rules this wallet does not implement,
  and a user who acts on them acts on a number that is not theirs;
- on the **wire** axis, reading is where the `#[serde(default)]` zero lives
  (§0.4): a read against a skewed daemon can succeed and be silently wrong,
  which is strictly worse than a submit that fails loudly.

Refusing at open closes both with one check and gives the operator the
message at the moment they can act on it.

**When it runs.** At open, and whenever the engine constructs or replaces its
daemon client. **Rejected for this round:** a periodic re-handshake during a
long session, to catch a daemon swapped underneath a running wallet. Reopen
when the RT transport posture takes up session-long peer binding; the
handshake is one more fact that binding should carry, and building a poller
here first would be building it in the wrong layer.

#### 3.6.4 Regtest — a typed acceptance, never a string

A `shekyld --regtest` daemon reports `nettype: "fakechain"`
(`cryptonote_core.cpp:423` sets `FAKECHAIN`); the regtest end-to-end suite
opens `Network::Mainnet` wallets against it, because fakechain shares
mainnet's address format and the address enum has no fourth variant. A
strict network check refuses every e2e run on day one.

**Proposed:** the network axis passes when `wallet.network` maps to the
daemon's `DaemonNetwork`, **or** when the daemon reports `Fakechain` and the
caller passed `FakechainPolicy::Accept` — a typed parameter of the open path
with a default of `Refuse`, set by exactly two callers: the regtest harness
(`regtest_e2e.rs`) and an explicit operator flag on the wallet binaries
(`--allow-fakechain-daemon`, or the existing regtest lever if one is ruled
equivalent). It is a type, not a string comparison and not an environment
variable: the fakechain schedule lever in `lifecycle/assemble.rs:407` is an
environment variable and is the precedent this deliberately does *not*
follow, because an env var is set once and forgotten and a typed parameter
is visible at every call site.

Rule 71 is respected: the network selects **data** (the value compared), and
the fakechain arm is not a consensus-surface divergence — it is a test and
developer harness lever, named, typed, defaulted off, and loud in the CLI's
`--help`.

### 3.7 `VC-D7` — genesis behaviour: a claimed property, with the constraint it imposes

Pre-genesis the constants file moves and the digest moves with it; a client
built before the move refuses a daemon built after it, names the axis, and
the developer rebuilds. That is the intended behaviour and it is how the
mechanism gets exercised before it matters.

At genesis the file freezes and the same comparison becomes an assertion of
**rules identity**: every client and daemon that agree on the digest were
built from the same consensus constants. Together with the network axis
(§2), that is chain identity, and it is **claimed as a property** of this
design, not left as an accident. Any post-genesis edit to the file produces
a digest no genesis-built client accepts, which is correct: an edit to the
consensus constants *is* a new rule set, and the one planned rule change in
Shekyl's life — the V4 lattice-only transition — is by definition a new
chain state that every party must opt into. This mechanism refuses silent
participation in it, which is the autonomy property
([`75-system-autonomy`](../../.cursor/rules/75-system-autonomy.mdc)) applied
to a client.

**The constraint the claim imposes.** The file's membership rule — *only
consensus-affecting constants live here* — becomes binding, not advisory. One
stray tunable (a default timeout, a UI constant) placed in this file makes
every client refuse every daemon built after it moved, for a change to
nothing that matters. `VC-1` adds that sentence to the file's leading
`_comment`, and the reviewer of any JSON addition owns the question "does a
different value of this make a different chain?" If the answer is no, the
constant does not belong in the file.

### 3.8 `VC-D8` — the P2P handshake does not carry the digest in this round

Peers with different consensus constants are a different and more serious
problem than clients with different constants, and the digest is exactly the
fact a peer handshake would want beside the network ID. **Rejected for this
round.** The P2P handshake is a consensus-surface commitment owned by the
P2P-2 design round (the B7/B8 drop-semantics work), it is Levin wire rather
than RPC, and its mismatch policy (drop? ban? score?) is a peer-management
question this round has no standing to answer.

**Reopening criterion:** P2P-2 takes up peer identity beyond the network-ID
bytes. `CONSENSUS_CONSTANTS_DIGEST` is then a ready-made value with pinned
canonicalisation; this document is the reference for what it means and does
not mean (§1).

### 3.9 `VC-D9` — the Python generator emits no digest

Rejected with `VC-D4`: no C++ consumer exists. **Reopening criterion:** a C++
consumer of the digest appears — which, given the direction of the FFI
boundary ([`20-rust-vs-cpp-policy`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)),
should first be asked whether it ought to be Rust.

### 3.10 `VC-D10` — no intra-binary agreement check

One daemon binary is a C++ half (consensus, `consensus_constants_generated.h`
at CMake configure time) and a Rust half (`build.rs` at cargo build time),
both reading the same file in the same tree. Could they disagree, so that the
digest the Rust half publishes describes a file the C++ half did not read?
`CMAKE_CONFIGURE_DEPENDS` on the JSON and `cargo:rerun-if-changed` on the JSON
make both regenerate on every edit; the existing `static_assert` /
`const _: () = assert!` sentinels pin both halves to the same values at every
consuming site; and a divergence would be a build-system defect with a blast
radius far larger than this check. **Rejected.** **Reopening criterion:** the
two halves are ever built from different trees — for instance a prebuilt Rust
image linked into a C++ build — at which point the digest should be emitted
on both sides and compared at daemon start, and `VC-D9` reopens with it.

### 3.11 `VC-D11` — the narrow `T` check is deleted when the general one lands

`console/info.rs`'s `daa_target_seconds` warning (§0.3) is a subset of the
rules axis. Once `VC-3` refuses a remote console on a digest mismatch, the
warning's condition (`reported != authority` on a daemon whose digest
matched) can only arise if the same file produced two different `T`s, which
the sentinels make impossible. It becomes unreachable, and unreachable code
that looks like a check is the class rule 47 exists for. **`VC-3` deletes
it** and its tests, and re-points the doc comment that names this round.
Rule 15: pre-genesis, delete rather than keep two instruments for one fact.

### 3.12 `VC-D12` — the digest's file set: `consensus_constants.json` alone, or all of `config/`?

Raised by the steering lane on 2026-09-05 while correcting a relay: the
fee-ladder implementation bundle touches `config/economics_params.json`, not
`consensus_constants.json`, so it would **not** trip `VC-1`'s sentinel — and
that is the gap. `economics_params.json` is at least as consensus-affecting
as the file `VC-1` digests: `money_supply`, the emission speed and final
subsidy, the burn rates, the staker shares, `coin` (the atomic-unit
denominator), `shekyl_tx_volume_window` (the fee ladder's window). What
guards it today is `rust/shekyl-economics/src/digest.rs`: a Blake2b-256 over
the typed `EconomicParams`, used as the C4 fixture-lineage guard and as one
leg of `snapshot_calibration_digest`. That is a **different instrument with a
different job** — it detects drift between a committed fixture and the
params, it does not fail the build against a pinned value, and its module
doc deliberately keeps it `EconomicParams`-only so fixture lineage does not
move when an unrelated constant changes. Its narrowness is correct for its
job; the consequence is that **seven** of `economics_params.json`'s eighteen
non-comment keys (`coin`, `display_decimal_point`, `shekyl_fixed_point_scale`,
`shekyl_tx_volume_window`, `shekyl_staker_emission_share`,
`shekyl_staker_emission_decay`, `shekyl_blocks_per_year`) have no build-time
guard of any kind. The honest answer to "what guards `economics_params.json`
against a client/daemon mismatch" is currently *nothing*.

**Proposed: the rules digest covers both integer authorities under `config/`
— `consensus_constants.json` and `economics_params.json` — as one digest,
one wire field.** The canonical form (§3.3) gains a per-file section: after
the header line, for each file in a fixed order, one line naming the file
(`= config/consensus_constants.json`) followed by its sorted `key value`
lines. Both files are already integer-only (18 of 18 in
`economics_params.json`), so rules 2–5 apply unchanged; the header bumps to
`…-canonical-v2` because the form changed. Two digests (one per file) were
considered and rejected: two wire fields for one question — "same rules?" —
and a second thing a client can forget to compare. Rule 19 says bundle by
validation surface, and the surface is "the constants this binary was built
from".

**A key rename moves the digest, and should.** The fee-ladder bundle's
`FL-R15` renames `money_supply` → `emission_curve_asymptote` with the value
unchanged. Under the canonical form the digest moves, because the key is
part of the binding: a constant is a *name* bound to a value, every
generator reads it by name, and a build where the name moved is a build
whose generators were rewritten. The re-pin question ("does a different
value of what moved make a different chain?") is answered for a rename by
asking it of the value the new name binds — the fee-ladder lane's own answer
for the asymptote is yes. The design does not add a value-only view to
excuse renames; a rename that is not worth a re-pin is a rename that should
not be made to this file.

**`genesis_recipients.{mainnet,stagenet,testnet}.json` are excluded from
the digest, and the genesis block hash becomes the tuple's fourth axis
(§2), in `VC-4`'s scope.** The files are per-network (which would break the
digest-is-orthogonal-to-network property §2 relies on) and non-integer
(strings and lists), so they do not fit the form; and what they determine —
the genesis block — is better checked directly, by comparing the daemon's
`on_get_block_hash([0])` (native since RK-2; no wire change) to a
per-network pinned genesis hash. **This document's first draft excluded them
on the claim that the genesis hash "already commits to them" and left the
comparison as a reopening criterion; the steering lane checked and the
criterion was already true — nothing pins a genesis hash in Rust and nothing
compares one.** An exclusion cannot rest on a check nobody performs, so the
check moves into scope: `VC-4` adds the Rust pins (per network, rule 71:
`nettype` selects the constant, never the control flow; derived from the
daemon's `GENESIS_TX`/`GENESIS_NONCE` and KAT-checked against a live daemon's
block 0 the way the txid KATs are) and the comparison, and refuses on
mismatch with the same shape as the other axes. Regtest: `FAKECHAIN` uses
mainnet's configuration, so a regtest daemon reports mainnet's genesis hash
and the axis passes for a `Mainnet` wallet under `FakechainPolicy::Accept`
exactly as the network axis does. **Reopen** the digest question for these
files only if the genesis-hash axis is ruled out.

**The named first consumer.** The C2-R2 weight/fee round does not touch
`consensus_constants.json` today, but its §8 names migrating the weight and
fee constants *into* it as a store-port obligation — they are hand-maintained
in `src/cryptonote_config.h` with a `shekyl-wire` mirror. The port PR that
executes §8 is the first change that will meet the sentinel, and that lane's
own read of the re-pin question is **yes for every one of them**: the
penalty-free zone, the clamps and the surge factor are consensus; the
relay-policy trio is admission-visible. That is the mechanism doing what it
is for — a key addition forced through the question rather than past it —
and it is recorded here so the first red is met as the design, not as a
surprise.

**Cost if ruled yes:** `VC-1`'s canonicaliser reads two files instead of
one, the KAT gains a two-file case, the sentinel's pinned value changes
once, the JSON `_comment` sentence moves to (or is duplicated in)
`economics_params.json`, and `shekyl-economics`'s digest keeps its job
untouched — two digests with different jobs is right; a gap between them
was not. **Not built ahead of the ruling** (rule 21: the one-file form is not
wrong, it is narrower than the surface, and widening it is Rick's call
because it decides what a "consensus constant" is for this project).

---

## 4. Implementation slices — named, not started

None of these is authorised to start by this document; §6 and the banner
say what is. Each slice runs the CI-exact gates
(`cargo fmt --all -- --check`; `cargo +1.94.0 clippy --workspace
--all-targets --keep-going -- -D warnings`; `cargo test --locked --workspace
--exclude shekyl-randomx-differential`) on the tree it pushes, plus the eight
doc gates, plus what each row names.

| Slice | Contents | Wire change? | Additional gate |
| --- | --- | --- | --- |
| **`VC-1`** — **BUILT** in this document's PR (`dev` e54e5b983) | `shekyl-rpc-types/build.rs` + `CONSENSUS_CONSTANTS_DIGEST` and `CONSENSUS_CONSTANTS_CANONICAL` (§3.3, §3.4), with the canonicaliser in `build_support/consensus_canonical.rs` included by both the build script and the tests — one definition; canonical-form KAT whose expected digest was computed by an independent Python implementation of §3.3; live-file sentinel (`const _: () = assert!`); `DaemonNetwork` type with string round-trip and unknown-string refusal tests; the membership-rule sentence in the JSON's `_comment` (§3.7). | **No.** Nothing on the wire moves; the constant exists and is tested; nothing reads it yet, and `consensus_digest.rs`'s module doc says so. | Red observed before trusting green, two ways: with the sentinel disabled, a descending key sort fails `kat_pins_the_canonical_form_and_its_digest` and `the_live_canonical_form_has_the_shape_the_design_pins` while `the_build_used_these_rules_on_the_live_file` stays green (build script and tests share the mutated rules — the Python-derived KAT is what catches a drift both sides share); with the sentinel enabled, the same mutation fails **compilation** on the pinned digest, which is the sentinel doing its job first. |
| **`VC-2`** | `GetVersionResponse` + 2 fields; `CORE_RPC_VERSION` → next minor, **read from `dev` at write time**; `get_version_synced_v5.json` and siblings for the other two `v1` states; chain-delta test extended per §3.5; chain-facts POD `nettype` byte + C export + ABI offset pin; `methods.rs` fills both fields. **Pre-flight pass first (rule 26).** | **Yes.** Needs Rick's ruling on alpha.8 timing (§6). | `rpc_parity` whole chain green; the four-spelling version pin updated; C++ `ninja -C build` + unit suite (the POD changed). |
| **`VC-3`** | Console remote arm handshake (§3.6.2); `version` exemption; delete `daa_target_seconds` and its tests (§3.11); operator-facing message tests for all three axes and both "older side" directions. | No (consumes `VC-2`). | A test per axis that observes the refusal on a fabricated mismatched reply, and one that observes `version` rendering both sides. |
| **`VC-4`** | Engine open-time handshake (§3.6.3) on all four axes, including the per-network genesis-hash pins and the `on_get_block_hash([0])` comparison (`VC-D12`); `OpenError::DaemonIdentityMismatch`; `FakechainPolicy` (§3.6.4) threaded through `open_*`, set by `regtest_e2e.rs` and the operator flag; **fix the `daemon.rs:169` docstring** to say what the code now does; `shekyl-cli` / `shekyl-wallet-rpc` messages per rule 82. | No (consumes `VC-2`). | Regtest e2e green with the policy passed; a lifecycle test per axis observing `open_full` refuse; a test that `FakechainPolicy::Refuse` (the default) refuses a `fakechain` daemon. |

`VC-1` landed with this document: the steering lane ruled (2026-09-05) that
code with no wire change and no C++ clears the throttle, and the enabler
ships with its own oracle (the KAT and the sentinel) rather than waiting for
a consumer that cannot exist until `VC-2` is authorised. `VC-3` and `VC-4` land in **one PR** with `VC-2` or
immediately after it on the same branch: producers and callers in one PR is
the standing rule, and a `get_version` field with no consumer would be the
very finding this round opened with, recreated.

---

## 5. Rejected alternatives, in one place

| Rejected | In | Reopens when |
| --- | --- | --- |
| Version compatibility window | `VC-D1` | post-genesis window wanted; must co-rule `deny_unknown_fields` and close the `#[serde(default)]` item |
| Per-constant comparison list | `VC-D2` | never as such — a list is what the digest replaces |
| Raw-bytes file hash | `VC-D2` | never — the canonical form is cheaper than the false alarms |
| Per-consumer `build.rs` copies / shared build-dep crate | `VC-D4` | a consumer that cannot depend on `shekyl-rpc-types` appears |
| Two-method handshake (`get_version` + `get_info.nettype`) | `VC-D5` | RK-5c lands a typed native `get_info` **and** the FFI byte proves costlier than the duplicated field |
| Local-console startup check | `VC-D6` | never — it cannot fail |
| Console "render anyway" override | `VC-D6` | an operator task `version` cannot serve is named |
| Wallet refuses submit only, reads allowed | `VC-D6` | never — §3.6.3 |
| Periodic in-session re-handshake | `VC-D6` | RT session-long peer binding |
| `Fakechain` in `shekyl_address::Network` | `VC-D6` | unchanged from `V3_WALLET_DECISION_LOG.md` :1397 |
| Digest in the P2P handshake | `VC-D8` | P2P-2 peer identity beyond the network ID |
| Python generator emits the digest | `VC-D9` | a C++ consumer, after asking whether it should be Rust |
| Intra-binary C++/Rust digest compare | `VC-D10` | the two halves built from different trees |
| Keep the `T` warning beside the digest | `VC-D11` | never — unreachable once `VC-3` lands |
| Two digests, one per config file | `VC-D12` | never as such — one question, one field |
| Value-only view that ignores key renames | `VC-D12` | never — a key is part of the binding |
| `genesis_recipients.*.json` in the digest | `VC-D12` | no client-side genesis-hash comparison exists when `VC-4` lands |

---

## 6. Rulings this round needs (Rick)

1. **The tuple and its carrier** (`VC-D2`, `VC-D5`): three axes, exposed on
   `get_version`, with the one-byte FFI widening for `nettype`. The
   alternative is the two-method handshake in §5.
2. **Alpha.8 timing of `VC-2`**: the wire change is the one thing in this
   document the steering direction holds. Land in alpha.8, or first thing
   after. **What a yes buys:** `VC-3` and `VC-4` land with `VC-2`, and `VC-4`
   now carries **four** axes, not three — the fourth adds per-network
   genesis-hash pins in Rust and no wire change (`VC-D12`, §2). Fold or
   split; but it should not be a surprise in the PR.
3. **The fakechain shape** (`VC-D6`, §3.6.4): a typed `FakechainPolicy`
   parameter with a default of `Refuse`, set by the regtest harness and an
   explicit operator flag — versus reusing an existing regtest lever, if one
   is ruled equivalent.
4. ~~Whether `VC-1` lands now~~ — **ruled by the steering lane 2026-09-05:
   yes** (no wire change, no C++). Built in this PR.
5. **The digest's file set** (`VC-D12`): `consensus_constants.json` alone
   (as built) or both integer authorities under `config/`, with
   `economics_params.json`'s seven unguarded keys as the argument for
   widening. If yes, `VC-1` widens before this PR merges (canonical form
   `v2`, one re-pin); if no, the doc must name what guards
   `economics_params.json` — today, nothing.

Until 1–3 and 5 are ruled the banner stays at round 1 and `VC-2`…`VC-4`
stay a table.

---

## 7. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-05 | **Round opened; the problem is two no-consumer facts, not one.** The dispatch named `CORE_RPC_VERSION` (§0.1, re-swept: 31 hits, zero comparisons). Grounding the network axis found the second: `get_info.nettype` has no Rust reader, `WALLET_REWRITE_PLAN.md` :216 lock 5 requires the daemon's network "verified via `get_info` before any wallet operation", the landed `OpenError::NetworkMismatch` compares the wallet file to the caller and never asks the daemon, and `engine/daemon.rs:169`'s docstring says the check is performed when it is not (§0.2). The regtest e2e suite passing `Mainnet` wallets against `fakechain` daemons is the proof the check is absent. **Recorded because it changes the round's shape:** the network axis is not a nice-to-have beside the digest, it is a Phase-1 commitment that never landed and has been claimed in prose as landed since. |
| 2026-09-05 | **The digest is orthogonal to the network ID, not stronger than it.** The parent's §7 sketch said "stronger than a network-ID byte, because it commits to the rules rather than to a label". Half right: the constants file has no per-network data, so mainnet, testnet and stagenet share one digest. Identity is digest **and** network (§2); the design carries both and refuses on either. |
| 2026-09-05 | **"Local console fatal at startup" rejected: it cannot fail.** `Source::Live` renders from the same binary that would answer; comparing a constant to itself is a check that exists to be seen. The remote arm is the only console consumer (§3.6.1). |
| 2026-09-05 | **Refuse reads, not only submits.** Dispatch text allowed that refusing to read "may be merely annoying". Two grounds against: a rules mismatch means the read is of a different chain; a wire mismatch is where the open `#[serde(default)]` silent-zero lives. Both are wrong-data failures, not inconvenience (§3.6.3). |
| 2026-09-05 | **Scope held to design by steering direction** (alpha.8 slowdown; design docs exempt, wire changes not). Slices named in §4; `VC-1` identified as landable without a wire change; nothing started. Reported to the steering lane as a package before implementation, per its request. |
| 2026-09-05 | **`VC-1` built in this PR under the steering lane's ruling; the canonicaliser has one definition and two readers.** `shekyl-rpc-types/build.rs` and the crate's tests `#[path]`-include the same `build_support/consensus_canonical.rs`, so the generator cannot drift from its oracle. Which raised the question the mutation test answered: if both share the rules, what catches a rules drift? The KAT's expected digest was computed by an independent Python implementation of §3.3 (`json` + `hashlib`), so a mutated Rust canonicaliser disagrees with a number it did not produce — observed: a descending sort fails the KAT and the shape test while the build-vs-test agreement test stays green. And above that, the live-file sentinel turns the same mutation into a compile error before any test runs. Two independent oracles for one function, which is what "the check's subject cannot silently empty" costs to actually claim. |
| 2026-09-05 | **The digest's file set is a ruling, not an assumption (`VC-D12`).** The steering lane, correcting its own relay that the fee-ladder bundle would trip the new sentinel (it touches `economics_params.json`, a different file), exposed that nothing pins that file: `shekyl-economics`'s Blake2b digest is a fixture-lineage instrument covering 11 of its 18 keys and deliberately so. Proposed: one digest over both integer authorities, per-file sections, canonical form `v2`; a key rename moves it on purpose; `genesis_recipients.*` excluded because the genesis hash already commits to them (reopen if no client compares that either). Not built ahead of Rick's ruling — deciding what a "consensus constant" is for this project is his, and the one-file form is narrower than the surface rather than wrong. §6 gains ruling 5. |
| 2026-09-05 | **The genesis-recipients exclusion rested on a check nobody performs; the genesis hash becomes the fourth axis.** `VC-D12`'s first draft excluded `genesis_recipients.*.json` from the digest because "the genesis block hash already commits to them", with "reopen if no client compares it by `VC-4`" as the criterion. The steering lane checked: the criterion is a present fact — no Rust genesis-hash pin, no client comparison, only the daemon's own `GENESIS_TX`/`GENESIS_NONCE` in `cryptonote_config.h`. Verified here rather than relayed. Third stated-commitment-without-enforcing-site found today, and this one was this document's own. Disposition restated: the files stay out of the digest (per-network, non-integer), and the comparison joins `VC-4` as the fourth axis over the existing native `on_get_block_hash` — no wire change. `FAKECHAIN` shares mainnet's genesis, so `nettype` remains the regtest discriminator and the operator-readable value. **The convergence is the point:** the lock-5 wrong-chain case is undefended on network *and* genesis simultaneously; the tuple is the enforcing site for both. |
| 2026-09-05 | **A second false docstring, found by the steering lane's independent check of §0.2.** `engine/error/mod.rs:41` lists `OpenError::NetworkMismatch` as "wallet file says network N, daemon client says network M" under "variant names locked in by the plan" — and the variant's fields are `{ wallet, expected }`, with no daemon-reported value anywhere in the comparison. Recorded with `daemon.rs:169` in §0.2; `VC-4` fixes both in the same PR as the check. The lock finding now leads the package to Rick: not a new capability for alpha.8, but a defence the plan committed to and the wallet has shipped without. |
