# WINDOWS_WALLET_SUPPORT.md

**Status:** Design round R0 — **open**, one ruling outstanding (Q-1, the
Shape-B transport model). Everything else in this document is decided and
recorded here rather than deferred.
**Verified against:** `shekyl-core` `dev` @ `69e76a7b` (every claim anchored
at file:line against that tree).
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
| B-1 | [`rpc_client.rs:302`](../../rust/shekyl-cli/src/rpc_client.rs) `http_post_uds` | `std::os::unix::net::UnixStream` | transport |
| B-2 | [`server.rs:278`](../../rust/shekyl-wallet-rpc/src/server.rs) `restrict_socket_perms` + [`:294`](../../rust/shekyl-wallet-rpc/src/server.rs) `private_socket_dir` | socket 0600 inside a 0700 dir | transport authz |
| B-3 | [`scripted.rs:18`](../../rust/shekyl-cli/src/commands/scripted.rs) `open_seed_out` | `OpenOptionsExt::mode(0o600)` | secret at rest |
| B-4 | [`disk.rs:88`](../../rust/shekyl-engine-core/src/engine/stake_engine/serving/disk.rs) `observe_disk` | `rustix::fs::statvfs` | mechanical |

**This list is a floor, not a ceiling.** It was produced by grep, and a
compile stops at the first error per crate. The lesson from #500 —
recorded as `include-only-is-not-unused` — is that a zero-symbol grep is a
hypothesis. §7 plans the run that turns this into a complete list.

## 3. The scoping fact that shrinks the problem

**External-server mode already works on Windows.** The CLI's `--rpc-url
http://…` path plus [`AuthConfig::Basic`](../../rust/shekyl-wallet-rpc/src/auth.rs)
over `ListenAddr::Tcp` is ordinary portable Rust. Nothing in this round
touches it.

What does not exist on Windows is **Shape B**, the self-hosted default:
the CLI spawns an in-process server over a private UDS socket and speaks
HTTP/1.1 to it ([`rpc_client.rs:15-17`](../../rust/shekyl-cli/src/rpc_client.rs),
[`:254`](../../rust/shekyl-cli/src/rpc_client.rs)).

Two consequences, both load-bearing for the design:

1. **The channel never crosses a process boundary.** Client and server are
   the same process; the socket path is generated, used, and dropped
   in-memory. So the Windows replacement needs **no new configuration
   surface, no name the user ever types, and no handoff to a child.**
2. **The full embedder set is two.** `spawn_in_process` is called only from
   [`rpc_client.rs:270`](../../rust/shekyl-cli/src/rpc_client.rs) and the
   crate's own test
   ([`tests/http_get_version.rs`](../../rust/shekyl-wallet-rpc/tests/http_get_version.rs)).
   `shekyl-gui-wallet` does **not** ride Shape B (verified: no
   `spawn_in_process` / `uds://` / `UnixStream` reference in its
   `src-tauri/src/`), so no cross-repo cutover is implied.

## 4. Q-1 — the Shape-B transport model (**RULING NEEDED**)

### Option A — Windows named pipe, owner-only security descriptor (recommended)

A random 128-bit pipe name under `\\.\pipe\`, created with a security
descriptor granting access to the creating user's SID alone, served with
`tokio::net::windows::named_pipe`.

- **Carries the guarantee.** Authorization is kernel-enforced at connect
  time against an ACL. That is the same *kind* of statement as 0600 on a
  socket, which is what "auth rides the transport" means.
- **No new surface.** Per §3 the name is internal; nothing is configurable,
  nothing is written to disk, nothing is passed between processes.
- **Costs**, stated honestly: an axum `Listener` implementation for the
  create-instance-per-accept model (real plumbing, not a `cfg` swap), and
  building the SD requires `unsafe` (see D-2).

### Option B — loopback TCP + a generated per-session credential

Bind `127.0.0.1:0`, generate a random password, use the existing
`AuthConfig::Basic`.

- **Cheap** — reuses live code, no new listener, no `unsafe`.
- **Rejected**, because it *converts a kernel-enforced property into a
  brute-forceable secret*. Every local process can reach a loopback port
  and attempt authentication; the wallet also becomes visible in the local
  TCP table. "Auth rides the transport" would become "auth is a password
  again", which is precisely the property the UDS design chose against.

### Considered and rejected: AF_UNIX on Windows

Windows 10+ has `AF_UNIX`, but Rust's std does not expose `UnixStream`
there, so it needs a third-party crate (rule 17 vetting), and — decisively
— the permission semantics that make 0600 meaningful are **not** specified
to transfer. A boundary we cannot state precisely is not a boundary.

**Recommendation: A.** B is a real option only if we are willing to
restate the security model, which is a bigger decision than the port.

## 5. Decisions taken in this document (not user rulings)

- **D-1 — pipe squatting.** The `\\.\pipe\` namespace is global and
  first-creator-owns, so a squatter could pre-create the name. Mitigated by
  a random name **and** `ServerOptions::first_pipe_instance(true)`, which
  fails creation loudly rather than joining an existing pipe. This is the
  exact analog of the existing attacker-planted-entry handling in
  `prepare_uds_path`, which fails rather than reusing a path it does not
  own — the parallel is deliberate.
- **D-2 — where the `unsafe` lives.** `shekyl-wallet-rpc` is
  `#![deny(unsafe_code)]` ([`lib.rs:18`](../../rust/shekyl-wallet-rpc/src/lib.rs));
  `shekyl-cli` is not. SD construction needs `unsafe` because tokio only
  exposes `create_with_security_attributes_raw`. **Decision:** a small
  dedicated `cfg(windows)` module carrying a scoped `#[allow(unsafe_code)]`
  with a written safety argument, rather than relaxing the crate-level
  `deny`. If B-3's DACL work shows the same primitives are needed in two
  crates, that module becomes its own crate instead of being duplicated
  (`delete-the-duplicate-dont-synchronize-it`).
- **D-3 — B-3, the seed file.** Create with an explicit owner-only DACL at
  `CreateFile`, reusing D-2's machinery. Not "best effort": the 0600 on
  this path is the difference between an exported seed being readable by
  one account or by every account on the box.
- **D-4 — B-4, the disk probe.** `GetDiskFreeSpaceExW`'s
  `lpFreeBytesAvailableToCaller` is the exact semantic analog of
  `statvfs`'s `f_bavail` — space available *to this writer*, which is what
  the module's own rationale already argues for. Already type-checked
  against `windows-sys 0.61.2`; that crate and its only dependency
  (`windows-link`) are **already in `Cargo.lock`**, so this adds no new
  supply-chain surface.
- **D-5 — the build gate comes off last.** `cmake/BuildRust.cmake` skips
  the Rust binaries for Windows targets. That gate is removed in the slice
  that makes them build, not before — a half-ported wallet that compiles is
  worse than an honest skip.

## 6. What this does *not* change

- No change to the Unix path. The 0600/0700 construction stays exactly as
  it is; Windows gets a parallel implementation, not a lowest common
  denominator.
- No change to external-server mode on any platform.
- No new user-facing configuration on any platform.

## 7. Verification plan (shaped by what this box can actually do)

This machine **cannot compile Windows targets**: `ring`'s build script
needs a C cross-compiler, mingw is not installed, and there is no root to
install it. That constraint is why the plan is explicit.

- **Local gate — the scratch-crate pattern.** Each Windows module is
  type-checked for `x86_64-pc-windows-gnu` in an isolated crate that
  depends only on `windows-sys`/`tokio` (pure Rust, no C build scripts).
  This is what validated D-4's call signature before it was ever committed,
  and it catches the API-shape errors that are otherwise a 25-minute CI
  round trip each.
- **Full-closure gate — CI only.** Nothing local can compile the whole
  binary closure for Windows.
- **One deliberate scouting CI run.** §2's list is a floor. The normal
  batching discipline (CI is ~2h) is **inverted once, on purpose**: an
  early run whose only job is to drain the remaining Windows error list,
  because it is the only available equivalent of "check the whole closure
  locally". Findings from it amend §2 before slicing is finalized.

## 8. Provisional slicing (ratified after the §7 scouting run)

| Slice | Content | Gate |
|---|---|---|
| W-1 | D-2 module + D-4 disk probe | smallest real Windows code; proves the unsafe-siting decision |
| W-2 | B-1/B-2 named-pipe listener + client, per Q-1 | the security boundary; the bulk of the work |
| W-3 | B-3 seed-file DACL | reuses W-1 |
| W-4 | Remove the D-5 build gate; Windows CI builds and smoke-tests both binaries; FOLLOWUPS entry closed | the gate comes off only here |

Sequencing note: W-4 is what actually restores a Windows wallet to release
archives, and until it lands the Windows release story is unchanged from
PR #500 — daemon yes, wallet no.
