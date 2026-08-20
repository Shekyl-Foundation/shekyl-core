# WINDOWS_WALLET_SUPPORT.md

**Status:** Design round R0 — **RULED 2026-08-19.** WP-Q1 is decided (named
pipe with an owner-only security descriptor). Every other question raised in
the round is decided here rather than deferred; **one** item remains open
(§9.2, with a reopening criterion). §9.1 closed on the §6 scope ruling.
**Verified against:** `shekyl-core` `dev` @ `fbd7e770a` (every claim
re-anchored at file:line against that tree — see §2's drift note).
**Decision authority:** Rick. Rulings recorded inline with dates.
**Origin:** surfaced by PR #500 (C1/C2 install cutover), the first time
`shekyl-cli` / `shekyl-wallet-rpc` were ever built for a Windows target.
Tracked since as `docs/FOLLOWUPS.md` → "Rust wallet stack: no Windows
support".

---

## 1. Why this is a design round and not a port

The Rust wallet stack does not compile for Windows. That is easy to
misread as a `cfg` sweep. It is not: three of the four blocking sites are
the **implementation of a security boundary**, and the boundary is stated
in the API contract as *"auth rides the transport"*
([`docs/api/wallet_rpc.yaml`](../api/wallet_rpc.yaml)).

The wallet RPC runs with HTTP authentication **disabled** in its default
mode. What makes that sound is not a credential — it is that the only way
to reach the socket is to already be the user who owns it, enforced by the
kernel. Port the code without porting that property and the wallet ends up
listening with no authentication and no transport-level authorization,
which is strictly worse than not shipping on Windows at all.

So the question this round answers is not "how do we make it compile" but
**"what is the Windows construction that carries the same guarantee".**

Mission §1 applies directly: security is a precondition, not a feature to
be traded for platform coverage.

## 2. The blocking surface, enumerated

Four sites. The first three are the security boundary; the fourth is
mechanical.

| # | Site | Unix mechanism | Nature |
|---|---|---|---|
| WP-B1 | [`rpc_client.rs:456`](../../rust/shekyl-cli/src/rpc_client.rs) `http_post_uds` | `std::os::unix::net::UnixStream` | transport |
| WP-B2 | [`server.rs:277`](../../rust/shekyl-wallet-rpc/src/server.rs) `restrict_socket_perms` + [`:293`](../../rust/shekyl-wallet-rpc/src/server.rs) `private_socket_dir` | socket 0600 inside a 0700 dir | transport authz |
| WP-B3 | [`scripted.rs:185`](../../rust/shekyl-cli/src/commands/scripted.rs) `open_seed_out` | `OpenOptionsExt::mode(0o600)` | secret at rest |
| WP-B4 | [`disk.rs:88`](../../rust/shekyl-engine-core/src/engine/stake_engine/serving/disk.rs) `observe_disk` | `rustix::fs::statvfs` | mechanical |

**Anchors re-verified 2026-08-19; three of the four had drifted** from the
R0-open version (WP-B1 `302→456`, WP-B2 `278/294→277/293`, WP-B3 `18→185`; only
WP-B4 held). None of the *claims* changed — the functions are where the round
said they were, doing what it said — but a line number that silently ages is
a citation a reader cannot check, and this document is meant to be checkable.
Re-anchor at every base move, not at the end.

**This list is a floor, not a ceiling.** It was produced by grep, and a
compile stops at the first error per crate. The lesson from #500 —
recorded as `include-only-is-not-unused` — is that a zero-symbol grep is a
hypothesis. §7 plans the run that turns this into a complete list.

## 3. What is and is not already portable — **corrected**

The R0-open version of this section made two claims that are wrong. They are
corrected here rather than quietly edited, because one of them was load-bearing
for the round's scope.

> **Wrong:** *"External-server mode already works on Windows."*
> **Right:** the `--rpc-url http://…` form does. The `--rpc-url uds:///path`
> form does not, and it is a real, supported, out-of-process transport.

> **Wrong:** *"The full embedder set is two"* (the two `spawn_in_process`
> callers).
> **Right:** that counted who *spawns the server*, not who *speaks the
> transport*. [`http_post_uds`](../../rust/shekyl-cli/src/rpc_client.rs)
> serves both the self-hosted and the external form.

I enumerated the wrong reference set — the same error the Phase-5 round spent
five instances learning ([`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md)
§Phase 5: *enumerate the reference set, then verify; never enumerate the
container*). The container here was "callers of `spawn_in_process`".

### 3.1 The seam that actually matters: self-hosted vs external

The code already draws it. [`rpc_client.rs:466-468`](../../rust/shekyl-cli/src/rpc_client.rs),
verbatim: *"self-hosted mode is trusted; this guards the external
`--rpc-url uds://` path."*

| Form | Who creates the endpoint | Trust | Windows status |
|---|---|---|---|
| **Self-hosted** (default) | the CLI itself, in-process; address read from `InProcessHandle.listen` in memory | trusted | needs the new transport |
| **External `uds://`** | a separately-run server the user names | **untrusted** (per the source comment above) | needs the new transport **and** the peer checks in §5 |
| **External `http://`** | a separately-run server | untrusted; `AuthConfig::Basic` over TCP | already portable, untouched |

Two consequences, both load-bearing:

1. **The self-hosted channel never crosses a process boundary.** Client and
   server are the same process; the address is generated, used and dropped
   in memory. So the replacement needs **no new configuration surface, no
   name the user types, and no handoff.**
2. **The external form is where the peer checks earn their keep.** There the
   client dials an endpoint it did not create, which is the only situation in
   which "who owns the other end" is a real question.

`shekyl-gui-wallet` does **not** ride either UDS form (verified: no
`spawn_in_process` / `uds://` / `UnixStream` reference in its
`src-tauri/src/`), so no cross-repo cutover is implied.

## 4. WP-Q1 — the Shape-B transport model — **RULED 2026-08-19**

**Ruling: Windows named pipe with an owner-only security descriptor.**
`tokio::net::windows::named_pipe`, served under axum.

### Why, against the alternatives

**Loopback TCP + a generated per-session credential — rejected.** It converts
a kernel-enforced property into a brute-forceable secret: every local process
can reach a loopback port and attempt authentication, and the wallet becomes
visible in the local TCP table. It also does not save the work it appears to
save — the credential has to live somewhere, so an ACL'd token file comes
back, plus a listening port, firewall prompts, no atomic port reservation, and
a token with a read window that lands in swap and backups. Strictly more
attack surface for strictly less enforcement.

**AF_UNIX on Windows — rejected, and the R0-open rationale was wrong.**
That version said the permission semantics "are not specified to transfer."
They are: Microsoft documents that connecting to an `AF_UNIX` stream socket
requires write permission on the socket, the same shape as the Unix model.
The rejection stands on different grounds — **the crate layer**. `tokio` has
no Windows `UnixListener`, so adopting it means hand-rolling mio registration
for a socket type tokio does not support *and* still writing the ACL code,
i.e. owning a transport implementation in order to keep a name. A wrong reason
that reaches a right conclusion is a defect in its own right (it stops the next
reader looking), so it is corrected rather than left standing.

### The named pipe is better than the Unix path we have, not merely equivalent

- **The DACL is applied atomically at creation** via `SECURITY_ATTRIBUTES` in
  `CreateNamedPipe`. The UDS path binds
  ([`server.rs:241`](../../rust/shekyl-wallet-rpc/src/server.rs)) and *then*
  chmods ([`:246`](../../rust/shekyl-wallet-rpc/src/server.rs)) — a real
  pre-chmod window, which the code's own comment concedes and mitigates by
  parenting the socket in a 0700 directory. The pipe has no window to mitigate.
- **Peer identity is retrievable** (`GetNamedPipeClientProcessId`,
  `ImpersonateNamedPipeClient`). The Unix path does not use `SO_PEERCRED`, so
  this is capability we do not currently have.
- **No filesystem residue** — no `UdsCleanup`, no stale-path-blocks-rebind.

### The cost, stated

**Round-trip qualification, from the first real run (2026-08-20).** The
descriptor *can* be read back as a string, which is what P-1 rests on — but the
returned form is **canonicalised**: Windows renders well-known SIDs as SDDL
abbreviations (`LA`, `WD`, `AU`), so it is not verbatim. Comparisons must be
structural, or restricted to SIDs with no abbreviation (a logon SID, `S-1-5-5-X-Y`,
has none). The first version of P-1 assumed verbatim and could not pass.

An axum `Listener` implementation for the create-instance-per-accept model
(real plumbing, not a `cfg` swap), and `unsafe` for the security descriptor
(see WP-D2).

## 5. Decisions

### WP-D1 — the pipe name is load-bearing, and per-user derived

The self-hosted UDS name is **predictable today**:
`shekyl-rpc-<pid>-<counter>/wallet-rpc.sock`
([`server.rs:302`](../../rust/shekyl-wallet-rpc/src/server.rs)). That is
harmless on Unix **because the 0700 parent directory carries the access
control** — the name does not have to.

**The pipe namespace has no parent-directory analogue.** So on Windows the
name and the DACL must carry what the directory carried. This promotes the
name from a nicety to a requirement; the two mechanisms are not independent.

**Derive the name from the user's SID string**, not the username (usernames
are renameable and not unique across local/domain; the SID is stable). Keep
the SID **literal, not hashed** — SID strings run ~45 characters against a
256-character limit, so hashing saves nothing and destroys the property below.

**The payoff is self-consistency.** With `\\.\pipe\shekyl-wallet-<SID>…` owned
by an SD granting that same SID, the client's check collapses to: *does the
pipe's owner SID equal the SID I embedded in the name I derived?* No separate
"who was I expecting" lookup, no configuration to get wrong. A squatter would
have to create a pipe carrying the victim's SID in its name while its owner
SID is necessarily the squatter's — which is exactly what the check detects.

Instance scoping follows §3.1's split: **self-hosted** appends pid + spawn
counter (mirroring `private_socket_dir`'s reasoning); **external** is
user-named, as `uds://` is today.

### WP-D2 — where the `unsafe` lives: **its own crate**

`shekyl-wallet-rpc` is `#![deny(unsafe_code)]`
([`lib.rs:18`](../../rust/shekyl-wallet-rpc/src/lib.rs)); `shekyl-cli` is not.
The R0-open version made a dedicated crate *contingent* on the primitives
being needed in two places. **They are**, and the round's own mitigations are
what forced it: the **server** builds the SD at creation (in the
`deny(unsafe_code)` crate), and the **client** verifies the owner SID and
integrity level (in the CLI's connect path). Same Win32 token/SID primitives,
two crates.

**Decision: a small dedicated `cfg(windows)` crate**, with a scoped
`#[allow(unsafe_code)]` and a written safety argument per entry point. Not a
duplicated module (`delete-the-duplicate-dont-synchronize-it`), and not a
relaxation of the crate-level `deny`.

### WP-D3 — squatting: three mitigations, and what each actually buys

Pipe-name squatting has no UDS analogue: the namespace is global and
first-creator-owns, so a hostile local process can pre-create a name. All
three land **with the transport**, not after it.

1. **`ServerOptions::first_pipe_instance(true)`** — creation fails loudly if
   the name is taken, rather than joining an existing pipe. The analog of
   `prepare_uds_path` refusing a path it does not own.
2. **Client-side owner-SID check before any secret is sent** (WP-D4).
3. **The unpredictable per-spawn name** (WP-D1).

**What each buys — and (1) and (3) are no longer security arguments.**
Under §6's scope ruling most of the squatting wargame collapses: a same-user
Medium-integrity squatter is out of scope, because it can read the wallet file
directly and does not need the pipe. What (1) and (3) buy is **DoS prevention
and namespace hygiene**, and they stay because they are free — `first_pipe_instance`
is a builder flag, and the name is being generated anyway. They are kept on
those grounds, not on security grounds, and should not be cited as security
later.

**(2) is the one that survives, and only for the case §6 names.** A
Low-integrity / AppContainer process running as the same user can create a
pipe name while being unable to read the wallet file or the CLI's memory. On
the **external** path the client dials a name it did not create, so the peer
check is what stops that process holding a wallet password. Cost: one
comparison, on a handle already open, at a call site being written anyway. If
it were new machinery it would fail §6's test and be dropped.

### WP-D4 — the client-side peer check: same-SID **and** same-integrity

**SID alone is not sufficient on Windows.** Mandatory Integrity Control is
orthogonal to SIDs: a **Low-integrity process running as the same user**
passes a same-SID check. Sandboxed contexts — browser renderers,
AppContainers, anything marked from the Internet — run Low by default, while
an ordinary user process runs Medium. MIC's no-write-up rule does not help
here: it blocks Low writing to High, not a Medium client writing *down* to a
Low-owned object.

So the check is **two comparisons on the same handle, at the same call site**:

1. the pipe's **owner SID** equals the connecting user's SID;
2. the pipe's **integrity level** is at least Medium.

Without (2), the check verifies "same user" and silently accepts "same user,
sandboxed."

**Server side, set a mandatory label (SACL) at creation** requiring at least
Medium integrity, so a Low-IL process cannot open our pipe. Note this is
insurance rather than a gap in the default: unlabeled objects are treated as
Medium, so the default already blocks Low-IL *access*. It is asserted rather
than inherited because a default is not a decision.

**These are different threats and only one is a squat defence.** The SACL
protects *our* pipe from Low-IL clients. The client-side IL check is what
stops *us* talking to a Low-IL server. A label on a pipe we never created is
irrelevant to a squatter.

### WP-D5 — cross-user connection: **refused, with no opt-in flag**

The client requires the pipe's owner SID to equal its own. There is **no
`--allow-cross-user` escape hatch.**

Three reasons, and the first is decisive:

1. **WP-D7 already forecloses the legitimate case.** The realistic cross-user
   scenario is a wallet daemon under a dedicated service account, which WP-D7
   closes by the front door. A flag would reopen it by the back door, leaving
   two rulings in tension in the same document.
2. **This is the flag users are told to add.** *"If you get a connection
   error, pass `--allow-cross-user`"* is a plausible line in a forum post, a
   support script, or a social-engineering message — and the failure mode is a
   wallet password sent to a process the attacker owns. Security flags whose
   absence produces a confusing error get added by people who do not know what
   they are waiving.
3. **The asymmetry favours omission.** Adding the flag later is trivial and
   non-breaking; removing one that shipped is breaking. And there is no
   worse-workaround pressure, because loopback TCP is rejected — so the only
   alternative to cross-user is running the wallet as your own user, which is
   the correct answer anyway.

**Ship instead of the flag** (rule 82): a refusal that names the mismatch
concretely — expected SID, found SID, and "run the wallet under your own
account". The error explains the security property rather than looking like a
bug to route around.

### WP-D6 — remote reachability: the DACL grants the logon SID **instead of** the user SID

Named pipes are addressable as `\\host\pipe\name` through the `IPC$` share, an
attack surface UDS does not have. Per-user naming does **not** address it: a
remote caller who knows the SID can construct the name.

**The DACL grants the logon SID, and grants nothing else.** The user SID stays
as owner and group — identity for the peer check to compare against — but is
**not** an ACE.

**Corrected 2026-08-20 (PR #516 review); the first version of this decision was
wrong in a way that left it unenforced.** It said to *"use the logon SID on the
DACL"* and described it as narrowing an already-narrow grant, and the
implementation duly emitted
`(A;;GA;;;<user-sid>)(A;;GA;;;<logon-sid>)`.

**Allow-ACEs are combined as a union.** The user-SID ACE alone authorises *any*
token for that account — another terminal-services session, a remote logon over
`IPC$`, a scheduled task — and a second allow-ACE cannot subtract from it. So
the logon SID narrowed nothing, and the descriptor was exactly as wide as if
WP-D6 had never been written. The decision was recorded, implemented, and inert.

The correction is not "add a deny" but **remove the user-SID grant**. The logon
SID is present in the token of every process in the current logon session and
absent from every other, so it is the only ACE that carries the session
boundary. It also subsumes the explicit `NETWORK` (S-1-5-2) deny that was this
decision's first answer, and covers terminal-services separation, which
S-1-5-2 does not.

**Consequence for the API:** the logon SID is a **required** argument, not an
`Option`. There is no honest fallback — a descriptor without it grants nothing
(useless) or falls back to the user SID (the bug above, reintroduced silently),
so `shekyl-win-sec` refuses to build one and `SidError::NoLogonSid` says why.
Every interactive and service logon has a logon SID, so the refusal is a
genuine "something is very wrong" path rather than a routine one.

**Pinned by a probe, not by this paragraph.** P-1 now asserts both halves: the
logon-SID ACE is present, *and* the user-SID ACE is absent. A design note that
says "grant only X" is exactly the kind of claim that decays into "grant X too",
and this round has now watched that happen once.

### WP-D7 — never a service, never SYSTEM

**`shekyl-wallet-rpc` must not run as a Windows service or as SYSTEM.** A
SYSTEM-owned pipe has no meaningful per-user identity to derive from, and the
whole model degrades to "whoever the DACL says" — which is the loopback-TCP
posture with extra steps.

Recorded as an **explicit rejection** so nobody adds a service wrapper later
as a convenience. Per-user derivation also means no admin rights to install or
run, and lines up with wallet files under `%LOCALAPPDATA%` rather than a
shared location.

### WP-D8 — WP-B3, the seed file

Create with an explicit owner-only DACL at `CreateFile`, reusing WP-D2's crate.
Not "best effort": the 0600 on this path is the difference between an exported
seed being readable by one account or by every account on the box.

### WP-D9 — WP-B4, the disk probe

**Siting corrected 2026-08-20.** The Windows arm lives in `shekyl-win-sec`,
not beside its caller. `shekyl-engine-core` is `#![deny(unsafe_code)]` and the
Win32 call needs `unsafe`, so by WP-D2's rule the dedicated crate carries it —
the subject being a disk rather than a descriptor does not change the rule.
The first version shipped the `unsafe` in `shekyl-engine-core` and did not
compile on Windows; nothing on Linux could see it, because the arm is `cfg`'d
out there.

`GetDiskFreeSpaceExW`'s `lpFreeBytesAvailableToCaller` is the exact semantic
analog of `statvfs`'s `f_bavail` — space available *to this writer*, which is
what the module's own rationale already argues for. Already type-checked
against `windows-sys 0.61.2`; that crate and its only dependency
(`windows-link`) are **already in `Cargo.lock`**, so this adds no new
supply-chain surface.

### WP-D10 — the build gate comes off last

`cmake/BuildRust.cmake` skips the Rust binaries for Windows targets. That gate
is removed in the slice that makes them build, not before — a half-ported
wallet that compiles is worse than an honest skip.

## 6. Scope, and what this does not change

**The adversary this round defends against, stated because everything below
depends on it.** A compromised same-user process at **Medium integrity or
above**, and any **Administrator / SYSTEM** compromise, are **out of scope on
both platforms.** Such a process can already read the wallet file, read the
CLI's process memory, and keylog the passphrase; defending the transport
against it is theatre. The round defends **the OS's own sandbox boundary** —
it declines to be the thing that lets a process cross a line the OS was
holding. It does not defend against an adversary who has already crossed it.

This is why WP-D4's integrity check is not defence-in-depth against an
unbounded adversary. It honours an existing boundary: a Low-integrity or
AppContainer process **cannot** read the wallet file or the CLI's memory —
the OS blocks it — but it **can** create a pipe name. A same-SID check that
ignored integrity would convert *"sandboxed, no access"* into *"holds your
wallet password"*, which is escalation **up** to user trust by something that
started below it. That is the exact inverse of the adversary above, and the
only reason any of the peer-check machinery earns its place.

The same premise governs the Unix path, and applies equally to a socket as to
a pipe. It is stated here for want of a platform-neutral home:
[`THREAT_MODEL_WALLET.md`](../THREAT_MODEL_WALLET.md) is scoped to wallet
**privacy** (it is the subaddress round's adjunct), so a local-host security
posture does not belong to it as written. **A reader looking for this ruling
should not have to find it in a Windows document** — relocating it is owed,
and is not this round's to do.

- **No change to the Unix path.** The 0600/0700 construction stays exactly as
  it is; Windows gets a parallel implementation, not a lowest common
  denominator.
- **No change to external `http://` mode** on any platform.
- **No new user-facing configuration** on any platform. WP-D5 is the reason
  there is no new flag, not an oversight.

## 7. Verification plan — **corrected 2026-08-19, the constraint is narrower than stated**

The R0-open version said this machine "cannot compile Windows targets." That
is **too broad, and it understated the local gate.** Measured:

| Surface | `--target x86_64-pc-windows-gnu` |
|---|---|
| `shekyl-win-sec` (windows-sys only) | **compiles** |
| SD-from-SDDL, token/SID read, `GetDiskFreeSpaceExW` | **compiles** |
| `first_pipe_instance` + `create_with_security_attributes_raw` + `NamedPipeServer::connect`, under the full axum/hyper/tokio graph | **compiles** |
| `shekyl-engine-core` | fails — `ring` build script needs a C cross-compiler |

**The real constraint: any crate whose dependency graph reaches `ring`.** That
is `rustls` (via `hyper-rustls` and `ureq`) and `rcgen` — i.e. everything that
can speak HTTPS. Nothing to do with Windows as such, and nothing to do with
ring signatures either; `ring` is a Rust wrapper around a BoringSSL fork.

Consequence: **the entire Win32 API surface this round depends on is locally
verifiable.** What is not is *integration into the crates that carry TLS*.

- **Pre-registration.** The probes and their predictions are committed
  *before* any Windows machine is touched, in
  [`WINDOWS_WALLET_PROBE_SHEET.md`](WINDOWS_WALLET_PROBE_SHEET.md). Each row
  names the **decision a failure revisits**, which is what turns a checklist
  into a decision rule — without it a failed probe becomes a bug report against
  the probe. They are `#[cfg(windows)]` tests plus one runner, so the Windows
  machine's output is exit codes rather than prose that has to be summarised
  back; nothing has to survive a session boundary because nothing is held in a
  session.

- **Local gate — direct, where the graph allows it.** `shekyl-win-sec` is a
  real workspace member and is checked for `x86_64-pc-windows-gnu` directly;
  no scratch crate is involved and nothing can drift from it. All four items
  the round was waiting on — `first_pipe_instance`,
  `create_with_security_attributes_raw`, the `GetSecurityInfo` / token-SID
  side of WP-D4, and the integrity-level query — are **discharged**.

- **The copy gate is gone, because its subject moved** (2026-08-20). WP-D9's
  Windows half used to live in `shekyl-engine-core`, which cannot be
  cross-checked here, so the probe suite held a byte-compared *copy* of it and
  a CI gate existed to prove the copy had not drifted.

  The first real scouting run made that arrangement untenable for a better
  reason: `shekyl-engine-core` is `#![deny(unsafe_code)]`, and the Win32 call
  needs `unsafe`, so **the merged probe did not compile on Windows at all**.
  The lint could not fire on Linux, where the arm is `cfg`'d out — the same
  blind-gate shape this round keeps meeting.

  WP-D2 already answered it: the dedicated `cfg(windows)` crate carries the
  `unsafe`. Moving the function into `shekyl-win-sec` restores the deny
  untouched, makes the real function directly compilable, clippy-able and
  testable for a Windows target, and **deletes the copy and its gate rather
  than maintaining them** (`delete-the-duplicate-dont-synchronize-it`). P-8
  now exercises what ships.

- **Full-closure gate — the Windows runner.** The `Windows (MSVC, daemon)` job
  has the pinned toolchain and a native C compiler, so it is the only place a
  TLS-carrying crate compiles for Windows at all. Two steps live there:

  - **`WP-W1: shekyl-win-sec compiles for Windows`** — blocking. The crate has
    no `ring` in its graph and is verified locally too, so a failure is a real
    regression rather than an environment artifact.
  - **`WP-W5 scouting: remaining Windows errors`** — `continue-on-error`,
    **informational by design and named as such**, the standing form of the
    one-shot scouting run this section used to plan. It does not gate, because
    the port is deliberately incomplete until WP-W5 and a red would only
    restate what WP-D10 already says. **WP-W5 flips `continue-on-error` off in
    the slice that makes it pass — that flip is the gate.** Until then its
    output is read by a human.

    Today it proves one thing outright: WP-D9's `GetDiskFreeSpaceExW` half is
    compiled *somewhere*, which no Linux runner can do.

  The distinction matters because this round has spent two commits on gates
  that passed while checking nothing. A permanently non-blocking step is that
  antipattern unless its non-blocking-ness is deliberate, documented, and has a
  named event that ends it. All three hold here; the `dalek_ff_group` step in
  `rust-audit-test.yml` is the existing precedent.

## 8. Slicing (ratified after the §7 scouting run)

| Slice | Content | Gate |
|---|---|---|
| WP-W1 | The WP-D2 crate + WP-D9 disk probe | **LANDED** with this round — `shekyl-win-sec` + the `cfg`-split probe; compiles for `x86_64-pc-windows-gnu`, blocking-gated on the Windows runner |
| WP-W2 | WP-B1/WP-B2 named-pipe listener + client, WP-D1 naming, WP-D3 mitigations 1 and 3, WP-D6 DACL | the security boundary; the bulk of the work. **Read §8.1 first** — three of the five error sites delete rather than port, and one required decision (the parse surface) is invisible to the compiler |
| WP-W3 | WP-D4 peer checks (owner SID + integrity) and WP-D5 refusal, on the external path | ships **with** WP-W2, never after — see WP-D3 |
| WP-W4 | WP-B3 seed-file DACL | reuses WP-W1 |
| WP-W5 | Remove the WP-D10 build gate; Windows CI builds and smoke-tests both binaries; FOLLOWUPS entry closed | the gate comes off only here |

**WP-W3 does not float.** WP-D3 makes the client-side check load-bearing for the
external path, so a WP-W2 that shipped alone would put a named-pipe client in
the tree that sends a wallet password before verifying who owns the pipe.

Sequencing note: WP-W5 is what actually restores a Windows wallet to release
archives, and until it lands the Windows release story is unchanged from
PR #500 — daemon yes, wallet no. The Windows CI job is currently named
`Windows (MSVC, daemon)` and builds `--target daemon`; **WP-W5 owns renaming it
back** and re-adding the wallet binaries.

## 8.1 WP-W2 preamble — what the scouting runs actually found

Written **before WP-W2 cuts code**, because the naive shape is to `cfg`-split
all five error sites and end up with a Windows arm full of stubs. Three of the
five delete rather than port.

### The error list, drained across two runs

`shekyl-engine-core` compiles for Windows as of the WP-D9 siting fix. The
scouting step then advanced and reported five errors, **all in one file**:

| Site | Error | What it is |
|---|---|---|
| [`server.rs:22`](../../rust/shekyl-wallet-rpc/src/server.rs) | unresolved import `tokio::net::UnixListener` | the listener |
| `server.rs:278` | `could not find unix in os` | `PermissionsExt` |
| `server.rs:279` | no `from_mode` for `Permissions` | `restrict_socket_perms` |
| `server.rs:294` | `could not find unix in os` | `DirBuilderExt` |
| `server.rs:305` | no `mode` for `DirBuilder` | `private_socket_dir` |

`shekyl-cli` was never reached — cargo stops per crate, and it depends on
`shekyl-wallet-rpc`. Its sites, enumerated statically: `scripted.rs:18` and
`:189` (WP-B3), `rpc_client.rs:460` (WP-B1). Zero sites beyond §2's original
list, and **zero pre-existing `cfg(unix)`/`cfg(windows)` gates** in either
crate, so nothing was already hidden behind one.

### The seam is at listener construction, not at five call sites

**One `cfg` split**, producing a `NamedPipeServer` or a `UnixListener`. The
platform-specific work sits in `shekyl-win-sec` — the crate built to hold it
(WP-D2) — and `server.rs` calls into it. Five splits at five call sites would
scatter the platform boundary across a file whose job is the serve loop.

### Three of the five DELETE rather than port

This is the part that a `cfg`-split-everything reflex gets wrong, and it is
wrong three times out of four:

- **`restrict_socket_perms` — no Windows counterpart, because its reason is
  gone.** Its own doc comment states the case: applied *after* `bind`, with a
  0700 parent making the pre-chmod window unreachable. `CreateNamedPipe` takes
  `SECURITY_ATTRIBUTES` **at creation** — the atomicity WP-Q1 was partly decided
  on. There is no post-creation step to port. The function does not gain a
  Windows arm; it ceases to exist on that platform.
- **`private_socket_dir` — all three of its jobs are subsumed or absent.**
  Access control moves to the DACL; collision-avoidance to the per-spawn random
  name (WP-D1); and its third job, clearing a stale directory left by a
  recycled pid, has *no analogue at all* — a pipe is a kernel object that
  vanishes when the last handle closes, so there is no residue to clean.
- **Only `server.rs:22` is a genuine substitution**: `UnixListener` →
  `NamedPipeServer`.

### The parse surface: WP-W2 must ANSWER this, not discover it

`parse_rpc_url` ([`rpc_client.rs:517`](../../rust/shekyl-cli/src/rpc_client.rs))
matches `uds://` with `strip_prefix` — a string comparison. **It compiles
perfectly on Windows** and returns `RpcUrlForm::Uds`. The failure surfaces
later and elsewhere, at `http_post_uds`.

So the compiler under-reports. It enumerates the *transport* sites; it will
never enumerate the *parse* surface that offers a transport the platform does
not have. Once WP-W2 ports `http_post_uds`, `uds://` on Windows goes from
"fails to compile" to "parses fine, then fails at connect with something
unhelpful" — strictly worse than today.

**Why it is invisible, stated precisely:** the platform constraint is encoded
in the **implementation of a transport**, not in the **type that selects it**.
`RpcUrlForm::Uds` is a platform-independent variant whose Unix-ness lives one
layer downstream, so the compiler learns of the constraint too late to check
the parse. No amount of care in porting `http_post_uds` changes that.

**The fix is the project's own principle — gate the variant, not the
implementation:**

```rust
enum RpcUrlForm<'a> {
    Http,
    #[cfg(unix)]
    Uds(&'a str),
    #[cfg(windows)]
    NamedPipe(&'a str),   // or: no variant at all
}
```

With the variant gated, the `uds://` arm **cannot compile** on Windows and the
compiler does enumerate the parse surface. The blind spot becomes a build
error. That is structural impossibility replacing a question nobody asked —
the same move as deleting `wallet2.cpp` rather than documenting that agents
should not extend it.

It also **forces the `npipe://` ruling rather than deferring it**: with no
`Uds` variant on Windows, that arm must become either an explicit rejection
naming the platform, or an `npipe://` arm. There is no third shape in which it
quietly parses.

**The stakes are a live security decision, not bookkeeping.**
[`rpc_client.rs:466-468`](../../rust/shekyl-cli/src/rpc_client.rs) already
calls the external form *"an untrusted `uds://` server"* in tree. If `npipe://`
ships, the client-side owner-SID check (WP-D4) is the only thing between a
mistyped — or attacker-suggested — pipe name and a passphrase.

**Status: OPEN, and the decision authority's to rule.** WP-W2 cites the ruling;
it does not make it.

### What §2's triple confirmation does and does not say

§2's list has now been confirmed three times: by grep at R0, by the
wallet-rpc errors, and by the static enumeration of `shekyl-cli`. Those
confirmations are real, and they say **nothing** about the parse surface.

A grep-derived enumeration of *Unix API usage* cannot contain a defect whose
signature is the **absence** of a platform check in a string match. The list
was confirmed; it is a list that could not have held this item. That is worth
recording, because "confirmed three times" reads as coverage and here it is
coverage of one class only.

## 9. Open and closed, with criteria

### 9.1 Pipe-instance semantics — **CLOSED 2026-08-19**, no probe needed

The open question was whether a second process can attach an *instance* to an
existing pipe name, and under what ACL. It was recorded as the one place the
round rested on a platform property unverifiable on the development box.

**It no longer changes any decision.** Enumerate the actors that could attach:

| Actor | Disposition |
|---|---|
| same-user, Medium integrity or above | **out of scope** (§6) — already has the wallet file and the CLI's memory |
| same-user, Low / AppContainer | **blocked** by the Medium mandatory label (WP-D4, asserted rather than inherited) |
| different user | **blocked** by the DACL (WP-D1) |
| Administrator / SYSTEM | **out of scope** (§6) |

Every remaining actor is either out of scope or already covered, so the answer
to "can a second process attach an instance" cannot move a decision either
way. Closed by the §6 scope ruling, **not** by verification — which is the
honest closure: the platform behaviour is still unknown to us, and the point
is that it has stopped mattering.

An earlier amendment argued the DACL cannot cover same-user attachment. That
is true and now irrelevant, and is **retracted** rather than sharpened: once
same-user-Medium is out of scope, the premise it was defending disappears.

§7's scratch-crate probe keeps its place — `create_with_security_attributes_raw`
and the SD construction are code that must compile and behave — but it no
longer carries a **design** question.

### 9.2 Per-user naming for a third-party external client

WP-D1's self-consistency property depends on the client having *derived* the
name. In the external form the user *supplies* it, so there is nothing to be
self-consistent with, and WP-D4's same-SID rule is what carries the check
instead. **Reopen if** a third-party client of the external `npipe://` form
appears, or when the peer check is documented in
[`wallet_rpc.yaml`](../api/wallet_rpc.yaml) as a client obligation —
whichever first. The contract trigger matters: that is the moment third
parties are expected to implement it, and therefore the moment it must be
importable rather than copyable.

**Placement is deferred, existence is not.** The check lives inline in the
CLI's external-connect path until a second consumer appears; it moves into the
WP-D2 crate then. Nothing inherits from that choice — the check is client-side,
above the wire, and changes no format, contract, or consensus surface — so
extraction later is mechanical. The distinction is the point: a named-pipe
client that sends a wallet password before verifying who owns the pipe is the
squatting attack fully realised, and it is exactly the kind of gap that looks
like polish in review.
