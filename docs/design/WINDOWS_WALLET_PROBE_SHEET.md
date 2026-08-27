# WINDOWS_WALLET_PROBE_SHEET.md

**Pre-registration for the Windows wallet round (WP).** Written and committed
**before any Windows machine is touched**, and deliberately so.

**Status:** pre-registered 2026-08-19 against `dev` @ `fbd7e770a`. **First run
2026-08-20** on the `Windows (MSVC, daemon)` CI job — 3 passed, 5 failed, and
one prediction was falsified in a way that also exposed a fail-open assertion.
Results in §4. Predictions not yet exercised remain claims about *documented*
behaviour, not observations. **2026-08-20, WP-W2:** P-16 added to §1; P-4,
P-10 and P-11 re-celled in §2 for the self-hosted-only ruling
(`WINDOWS_WALLET_SUPPORT.md` §8.1).

**2026-08-27: P-17 registered in §3, prediction first and code second — this
commit carries no implementation.** It takes the half of WP-D6 that P-13 does
not: `IPC$` reachability, which is the attack surface D6 was written for, where
terminal-services separation is the same mechanism's secondary benefit. **P-13
is not superseded and is not reshaped** — §5 forbids editing a pre-registration
to fit, so it stays registered and visibly unrun. The two ask different
questions of one underlying property: that the logon SID is unique to its logon
session and absent from every other. Nothing in this sheet has tested that
property; P-1 and P-15 establish only that the DACL grants exactly one ACE and
that the SID is well-formed. Since PR #516 removed the user-SID grant, that one
ACE is the whole session boundary.

**Why this exists.** [`WINDOWS_WALLET_SUPPORT.md`](WINDOWS_WALLET_SUPPORT.md)
rules a transport whose security properties have never been executed by anyone
on this project. That is exactly the condition in which an unprepared
observation gets rationalised: a descriptor will be printed, it will look
plausible, and *plausible* becomes *verified* without anything having been
falsified. Recording the prediction first is what makes a wrong answer
recognisable as wrong.

**The column that does the work is "Revisits on failure."** A checklist tells
you what to look at. A decision rule tells you what a result *costs*. Without
it, a failed probe becomes a bug report against the probe.

---

## 0. How this is meant to be consumed

**Not by reading it on the Windows box.** The probes are `#[cfg(windows)]`
tests in `shekyl-win-sec` plus one PowerShell runner, so the Windows machine's
output is **exit codes**, not prose that has to be summarised back to a
reviewer. Nothing needs to survive a session boundary because nothing is ever
held in a session.

```powershell
# One command. Same script CI runs; -CiOnly drops the probes that need an
# interactive logon.
pwsh scripts/ci/windows_probe.ps1
```

**CI is the durable half.** A laptop run verifies once; the
`Windows (MSVC, daemon)` job verifies on every commit forever. That difference
is the whole reason §9.1 can be *closed* rather than silently re-opened the
next time tokio bumps a version. The laptop is for **iterating until the tests
pass** — a fast local loop, which CI is not.

**A `#[ignore]` here is a finding, not a workaround.** If a probe cannot be
made to run in CI, it moves to §3 with a recorded result and a date. Marking it
ignored and moving on is the failure mode this sheet is written against.

---

## 1. CI-durable probes

Run on `windows-2025-vs2026` as an unprivileged account with no interactive
session. These are `cargo test -p shekyl-win-sec` unless noted.

| # | Question | How | Predicted | Revisits on failure |
|---|---|---|---|---|
| P-1 | Does the SDDL string produce the DACL we meant? | Build the descriptor, read it back with `ConvertSecurityDescriptorToStringSecurityDescriptorW`, compare to the input | Round-trips with the **logon-SID** allow-ACE present, the **user-SID** allow-ACE absent (allow-ACEs union, so granting both would undo WP-D6 — this is the PR #516 finding), the exact `(ML;;NW;;;ME)` label present and no lower one, and no broad principal (`WD`/`AU`/`BU`) | **WP-D2** — if the OS does not preserve what we wrote, SDDL is not the reviewable-string win it was chosen for. **WP-D6** — the user-SID half is what made that decision inert once already |
| P-2 | Is the DACL *protected* (`D:P`) — no inherited ACEs? | Assert `SE_DACL_PROTECTED` in the control word | Set | **WP-D1** — an unprotected DACL means ancestry can widen access, and the name+DACL pair stops carrying what the 0700 dir carries on Unix |
| P-3 | Does `first_pipe_instance(true)` fail when the name is taken? | Create the pipe twice in one process; second call must `Err` | `Err`, and **not** a silent join | **WP-D3 (1)** — if it joins, the loud-failure property is gone and squatting stops being DoS-only even on the self-hosted path |
| P-5 | Does the peer check return the right owner SID? | Connect client→server in-process, run `PeerCheck::verify` | `Ok` | **WP-D4** — a false negative here makes the wallet unusable; a false positive makes the check theatre |
| P-6 | Does the peer check *refuse* a mismatched SID? | `verify` against a deliberately wrong expected SID | `Err(OwnerMismatch)` | **WP-D4/WP-D5** — this is the bite check. A check that never refuses is the fail-open shape this project has now hit six times |
| P-7 | Is an **unlabelled** pipe read as Medium (a pass)? | Create without a SACL, verify | `Ok` — absence is Medium, not failure | **WP-D4** — if absence reads as failure, every ordinary pipe is refused and the wallet cannot start |
| P-8 | Does the disk probe return sane numbers on a real volume? | `shekyl_win_sec::free_bytes_available` on `%TEMP%` — **the shipping function**, not a copy (the Windows arm moved into this crate on 2026-08-20, which deleted the copy and its drift gate) | `Ok(n)`, `0 < n <` volume size; and `Err` for a nonexistent path | **WP-D9** — a wrong figure silently disarms the operator-alarm headroom condition |
| P-14 | Is a **truncated** mandatory-label ACE refused rather than read? | Hand-build a SACL whose label ACE declares `SubAuthorityCount = 200` inside a 20-byte ACE; call the parser | `None` (malformed-refuse) — **not** `Some(Medium)` | **WP-D4** — `SYSTEM_MANDATORY_LABEL_ACE` embeds only the first DWORD of a variable-length SID, so a size check against the struct proves nothing about the sub-authorities. If this returns a level, the RID read walked off the end of an attacker-supplied ACE and a hostile server's malformed label is being trusted |
| P-15 | Is the logon SID actually a **logon** SID? | `current_logon_sid()` must return `S-1-5-5-<high>-<low>`, five dashes, and differ from the user SID | Holds | **WP-D6** — `SE_GROUP_LOGON_ID` is a two-bit marker, so a partial-bit match would select some other group this token belongs to and the DACL would grant *that* group. Invisible to the client-side owner check, because the owner would still be us |
| P-16 | Is the exported **seed file** owner-only from creation, and does creation refuse an existing path? | `shekyl_win_sec::create_owner_only_file` on a temp path; owner read back **literally** via `GetSecurityInfo(SE_FILE_OBJECT)` + `ConvertSidToStringSidW`; DACL asserted **structurally** from SDDL; a second create on the same path | Owner equals `current_user_sid()` (explicit `O:`, so not `BUILTIN\Administrators` even on an admin account — P-7's platform fact); `D:P` with exactly one ACE, `FA`; second create `Err` | **WP-D8** — a wrong owner or a second ACE means the seed is readable beyond the account that exported it, which is the whole difference `0600` makes; a successful second create means the `O_EXCL` half is missing and an existing seed file would be clobbered. Registered 2026-08-20 with WP-W2 (which absorbed WP-W4) |
| P-9 | Does the round-tripped SID match `whoami /user`? | Compare `current_user_sid()` against `whoami /user /fo csv` | Equal | **WP-D1** — the pipe name is derived from this; a wrong SID means the name and the DACL key on different values and self-consistency is lost |

## 2. Registered but not implemented

Three kinds live here, all stated rather than quietly dropped — a probe that
disappears from the sheet is indistinguishable from one that was answered:
P-4, unimplemented and **decision-relevant again** since 2026-08-20 (its row
says why, and what it needs); P-10, which exists as an ordinary test that no
blocking lane runs yet; and P-11, which WP-W2 made a property of a type
rather than something to observe.

| # | Question | Why not implemented | Revisits on failure |
|---|---|---|---|
| P-4 | Can a *second process* hold our name before we create it — and does **our** `first_pipe_instance(true)` create then fail loud, cross-process, the way P-3 shows in-process? | **Not implemented; decision-relevant since 2026-08-20.** The first form of this row said its revisit cell was *Nothing*, because §9.1 had closed on the scope ruling. That was correct for §9.1's question (who may attach *after* we hold the name) and wrong for this one (who may hold it *before*), which `WINDOWS_WALLET_SUPPORT.md` §8.1 identified as the 0700 directory's containment job. Predicted: a second process's `CreateNamedPipe` with `FILE_FLAG_FIRST_PIPE_INSTANCE` on a name we hold fails with `ERROR_ACCESS_DENIED`; ours fails the same way on a name it holds. Needs a second process (a self-re-exec helper would do); not written in WP-W2 because a helper that has never run once locally is the harness-artifact shape the first run of P-3/P-5/P-6 already produced. Named as a follow-up, not quietly dropped | **WP-D3 (1)** — if the flag does not fail loud on a taken name, the create-side half of containment is missing and the dial-side peer check carries containment alone. A stale *Nothing* here was worse than a blank |
| P-10 | End-to-end CLI ↔ wallet-rpc over the pipe | **Exists as an ordinary cross-platform test, not yet as a CI-durable probe.** *2026-08-21:* the wallet-rpc half was **observed passing** on the Windows runner (§4.3); the cli half has not yet executed there. WP-W2 (2026-08-20) gives `shekyl-cli`'s `rpc_session_e2e` a Windows arm that self-hosts, dials through `open_verified`, and round-trips `get_version`. It runs on no blocking lane until WP-W5 turns the wallet test lane on; the Windows runner's scouting step (`continue-on-error`, §7) runs it informationally until then. Stays here rather than moving to §1 because a §1 row whose test executes nowhere would be the coverage claim this sheet exists to refuse | **WP-Q1** — if axum cannot be driven over create-instance-per-accept without unacceptable complexity, the transport ruling itself is what gets revisited, not the plumbing |
| P-11 | Does a passphrase ever cross the pipe **before** `PeerCheck::verify` returns `Ok`? | **Made structural in WP-W2 (2026-08-20) rather than probed.** The only pipe-open path in `shekyl-cli` is `shekyl_win_sec::open_verified`, which runs `verify` before returning a handle; a write before `Ok` has nothing to write to. A runtime probe would be testing the type system. The reviewable check is the absence of any other pipe open in `shekyl-cli` (`CreateFileW`, `ClientOptions::open`, or a `\\.\pipe\` path in an `OpenOptions`) | **WP-D3 (2)** — ordering is the whole property; a check that runs after the first write is decoration |

## 3. Laptop-only, with a recorded result

**These are pre-declared as CI-fragile rather than discovered to be.** CI runs
as a fresh unprivileged account with no interactive logon, so two things this
round depends on may not reproduce faithfully there. Deciding that here is the
point: the alternative is finding out when a test is flaky and someone reaches
for `#[ignore]`.

| # | Question | Why not CI | Predicted | Revisits on failure |
|---|---|---|---|---|
| P-12 | Does the Medium mandatory label block a **Low-IL** opener? | Needs a genuinely Low-integrity process. Creating one wants an interactive token to derestrict from; a CI service account's token may not be a faithful source | Low-IL open fails with `ERROR_ACCESS_DENIED` | **WP-D4** — this is the *only* in-scope adversary per §6. If the label does not block, the server-side half of D4 is doing nothing and the client-side IL check becomes load-bearing alone |
| P-13 | Does the logon SID separate terminal-services sessions? | Needs two concurrent interactive logons | A second session's process cannot open the pipe | **WP-D6** — if it does not separate sessions, the logon SID is not the improvement on an `S-1-5-2` deny that D6 claims, and the explicit `NETWORK` deny comes back |
| P-17 | Does the logon SID **by itself** refuse a caller from a different logon session — the `IPC$` reachability WP-D6 exists for? Registered 2026-08-27, **corrected the same day before any run** (see below: production carries a second fence the design doc never recorded) | Needs a loopback SMB path (`LanmanServer` + the `IPC$` share) to produce a network logon. Whether the CI runner has one is **unverified**, and asserting either way is the defect class §5 is written against. Reports UNRUN when the precondition is absent — never a pass | Four, and the fourth is the one that attributes the result: (a) **control** — the pipe opens locally via `\\.\pipe\…`, proving it works and the DACL admits us; (b) **mechanism** — a caller arriving over loopback carries a logon SID *different* from `current_logon_sid()`; (c) **production shape** — a pipe built exactly as `create_instance` builds it (owner-only DACL **and** `reject_remote_clients(true)`) refuses the loopback open; (d) **the D6 claim proper** — a pipe with the same owner-only DACL but `reject_remote_clients(**false**)` *still* refuses it, with `ERROR_ACCESS_DENIED`. Only (d) isolates the logon SID | **WP-D6** — if **(d)** succeeds, the logon SID does not carry the `IPC$` boundary on its own, removing the user-SID ACE in PR #516 bought nothing on that axis, and the flag is load-bearing where the doc says the SID is. If **(c)** succeeds, production itself is reachable over `IPC$` and that is a live hole rather than a documentation one. If (b) fails the probe is **UNRUN**, not a pass: any refusal would then be unattributed |

**P-17's section is itself undecided, and that is why it is here.** §1 would
claim CI-durability nobody has established; §3 pre-declares CI-*fragility*,
which is also unestablished. It sits in §3 because that is the section whose
protocol tolerates a probe that may not run — it reports UNRUN and the blank
stays visible — where a §1 row that silently skipped would be the coverage
claim this sheet exists to refuse. **Promotion criterion:** if it runs green on
the CI runner, it moves to §1 and becomes a `#[test]`; "CI is the durable half"
(§0) and a probe that only a laptop ever executes verifies once.

**Why the mechanism row (b) exists, and why a refusal alone would not do.**
§4.2 records P-7 failing because it never reached the label path it existed to
test — it was refused, and the refusal looked exactly like a pass. A loopback
open that fails could equally mean the SMB path is absent, the share is
disabled, or the name resolved somewhere unexpected. So the probe first
connects a **deliberately permissive** second pipe over the same loopback path
and reads the caller's logon SID off the impersonation token: only once that
SID is observed to differ from ours is a refusal on the restrictive pipe
attributable to the logon-SID ACE rather than to the transport.

**The claim being measured, stated as a claim.** That a loopback SMB open
produces a *distinct logon session* server-side is documented behaviour we have
never observed. It is row (b), not a premise — the same discipline that turned
"a Low-IL thread is not a Low-IL opener" from a confident sentence into a
measured falsehood.

### 3.1 P-17's correction, made before the first run

**Production has two fences against `IPC$`, and this sheet's first form of P-17
knew about one.** `pipe.rs::create_instance` sets
`reject_remote_clients(true)` — `PIPE_REJECT_REMOTE_CLIENTS` — on every
instance, so a remote client is refused by the pipe *flag*, before any DACL
evaluation. **`WINDOWS_WALLET_SUPPORT.md` records this nowhere**; WP-D6 reads
as though the logon-SID grant is the whole answer, and the only place the
second fence appears is a code comment which asserts it is "a second fence
against the `IPC$` path WP-D6's logon-SID grant *already closes*".

That assertion is the thing P-17 exists to test, written as settled fact. It is
the same class this round has spent itself on, so it is named here rather than
inherited.

**What it changes.** With both fences up, a refused loopback open proves
nothing about the logon SID — it is the P-7 shape again, a refusal that looks
like a pass. So the probe must **lower the flag it is not testing**, exactly as
P-12 built a descriptor *without* the mandatory label to attribute its refusal.
Row (d) is the D6 claim proper: same owner-only DACL, `reject_remote_clients`
**off**, and the open must still be refused. Row (c) keeps the production shape
so the two are distinguishable.

**What it does not change.** P-17 is now explicitly a **defence-in-depth
verification, not a live-hole test.** Production is closed either way while the
flag is set; what is unverified is whether the layer WP-D6 *names* would hold
if the flag were ever removed — which is exactly the question a defence-in-depth
claim has to be able to answer, and which no one has asked.

**Recording protocol.** A §3 result lands as a dated row appended to §4 below,
naming the machine and Windows build. An unrun probe stays visibly unrun — a
blank is a finding.

## 4. Results

| Date | Probe | Machine / build | Result | Consequence |
|---|---|---|---|---|
| 2026-08-20 | P-2 (protected DACL) | `windows-2025-vs2026`, CI | **PASS** | `D:P` survives the round trip; WP-D1 holds |
| 2026-08-20 | P-8 (disk probe) | `windows-2025-vs2026`, CI | **PASS** | WP-D9's `GetDiskFreeSpaceExW` half returns a sane figure and refuses a bad path |
| 2026-08-20 | P-9 (user SID) | `windows-2025-vs2026`, CI | **PASS** | The SID the pipe name derives from is well-formed and stable |
| 2026-08-20 | P-1 (SDDL round-trip) | `windows-2025-vs2026`, CI | **FAIL — prediction wrong** | See §4.1 |
| 2026-08-20 | P-3, P-5, P-6, P-7 | `windows-2025-vs2026`, CI | **FAIL — harness defect** | `there is no reactor running`; the pipe probes were plain `#[test]` and tokio's named-pipe constructors register with a runtime. Now `#[tokio::test]`. No design consequence — they measured nothing, which is different from measuring a pass |

### 4.1 P-1: the prediction was wrong, and its failure exposed a second defect

The descriptor came back as:

```text
O:LAG:LAD:P(A;;GA;;;S-1-5-5-0-774477)S:(ML;;NW;;;ME)
```

**The policy is correct** — protected DACL, a single ACE, that ACE is the logon
SID, Medium label present. **The prediction's method was wrong:** Windows
**canonicalises well-known SIDs to SDDL abbreviations** on readback, so the
owner rendered as `LA` rather than `S-1-5-21-…`, and an assertion looking for
the literal owner SID could never pass on this account.

Per §5 the prediction stays on the record as having been wrong. What changes is
narrower than a decision: **WP-D2's claim that the policy "comes back out as a
string and can be compared" survives, with the qualification that the returned
string is *canonicalised*, not verbatim.**

**The second defect is the one worth the run.** The WP-D6 union check added in
PR #516's earlier review round asserted
`!contains("(A;;GA;;;<literal user SID>)")`. That is **fail-open**: a
regression granting the user SID would render as `(A;;GA;;;LA)` on any account
whose SID has an abbreviation, and pass. A check that cannot fail on the thing
it guards is the defect this whole round keeps finding, and it was introduced
*by a fix for a previous instance of it*.

P-1 now asserts the DACL **structurally** — exactly one ACE, and it is the
logon SID's (session SIDs are `S-1-5-5-X-Y` and have no abbreviation, so they
are safe to match literally). Owner identity moved to P-5, which reads SIDs off
a real object via `ConvertSidToStringSidW` — always literal — so it is not
exposed to canonicalisation at all.

**None of this touched the implementation.** `PeerCheck` compares SIDs read
from the object, never SDDL text, so the runtime check was never affected. The
defect was entirely in how the probe *asked*.


### 4.2 Second run: 7 of 8 pass; P-7 finds a platform fact

`895129d95`, same job. P-1 (rebuilt structurally), P-2, P-3, P-5, P-6, P-8 and
P-9 all **PASS** — which confirms at first hand that the WP-D6 correction works:
P-1's readback shows a protected DACL holding exactly one ACE, the logon SID's.

**P-7 failed, and its failure is worth keeping.** It refused with
`OwnerMismatch`: the pipe was owned by `S-1-5-32-544` (`BUILTIN\Administrators`)
while the process ran as `S-1-5-21-…-500`. P-7 had created the pipe with a
**default** descriptor in order to get "no mandatory label", and on an account
in the Administrators group Windows gives a default-owner object the
*Administrators group* as owner, not the user. So it never reached the label
path it exists to test.

**The platform fact, recorded because it is a latent hazard:** any pipe we
create **without an explicit owner** would be refused by our own peer check on
an administrator account. Production never does — every descriptor comes from
`OwnerOnlyDescriptor::new`, which sets `O:` explicitly, and P-1's readback
(`O:LA`) plus P-5/P-6 passing confirm it. But a future code path that took the
OS default would fail in a way that looks like a permissions bug rather than a
missing owner.

P-7 now builds our own descriptor minus the label
(`without_label_for_testing`), so the label path is the only thing under test.
Both constructors route through one `build()` so the label is the sole
difference between them.

---

### 4.3 Third run (PR #526 head `abb4e58dd`, 2026-08-21): P-16 passes; the scouting step finds the first Windows-only wallet bug

| Date | Probe | Machine / build | Result | Consequence |
|---|---|---|---|---|
| 2026-08-21 | P-16 (seed file owner-only, `CREATE_NEW`) | `windows-2025-vs2026`, CI | **PASS** (first execution; 11/11 probes green) | WP-D8 holds: explicit `O:` survives on the admin runner (P-7's platform fact did not bite), one `FA` ACE, second create refused |
| 2026-08-21 | P-10, wallet-rpc half (`spawn_in_process_serves_get_version_over_the_verified_pipe`) | `windows-2025-vs2026`, CI, scouting step | **PASS** — the first execution anywhere of the self-hosted pipe under axum with the verified dial | The documented-behaviour claims WP-W2 shipped on are now observations: a server-side close reads as EOF on the client (`Connection: close` round-trips), `open_verified` accepts our own pipe, and `first_pipe_instance` + descriptor-on-every-instance serve a real request |
| 2026-08-21 | P-10, cli half (`rpc_session_e2e`) | — | **NOT RUN** | The scouting step aborted on the failure below before reaching it. Unobserved, not passed |
| 2026-08-21 | (not a probe) `lifecycle_create_open_close_change_password` | `windows-2025-vs2026`, CI, scouting step | **FAIL** — `open_wallet` returned `-32603` where `-29004` was expected | **First Windows-only wallet bug, and not in the transport.** `WalletFile::open` took the keys-file lock (`fd-lock` → `LockFileEx`, byte 0) and then read the file through a *second* handle (`std::fs::read(path)`). `LockFileEx` is **mandatory**, not advisory: the second handle's read fails with `ERROR_LOCK_VIOLATION`, which became `WalletFileError::Io` → the RPC's text classifier → `-32603`. Every `open` on Windows failed this way; the Windows-green tests only ever `create`. Fixed by reading through the locked handle (`KeysFileLock::acquire_and_read`), with a unit test pinning the platform fact. The review of that fix found the sibling: `WalletFile::verify_password` read the path lock-free *by design* (so it could run while the wallet was open), which is the same second handle — every first-stake attempt on Windows would have failed the same way. It now verifies a snapshot of the envelope taken from the open handle (`sealed_keys_envelope`). Found by the informational step — whose conclusion the run page showed as **success** |

**Reporting consequence.** The failure above was invisible on the run page:
a `continue-on-error` step reports `conclusion: success` whatever its
command did, and the real result was ~8,000 log lines deep. The scouting
step now runs all three of its commands regardless of earlier failures,
writes a per-command exit table to the job summary, and fails the step (still
non-blocking) when any command failed — so "informational" means *reported*,
not *buried*.

### 4.4 Fourth run (`dev` @ `4a76f490a`, 2026-08-23): the first machine with an interactive logon, and P-12's first result anywhere

`LP7760-W1XMP6G3`, Windows 11 Enterprise 23H2 `10.0.22631.7517`, one console
session, Medium integrity, not elevated; `rustc 1.94.0` per `rust-toolchain`.
This is the machine §3 was waiting for — every prior run was CI, which has no
interactive logon.

| Date | Probe | Machine / build | Result | Consequence |
|---|---|---|---|---|
| 2026-08-23 | P-1, P-2, P-3, P-5, P-6, P-7, P-8, P-9, P-14, P-15, P-16 | `LP7760-W1XMP6G3`, `10.0.22631.7517` | **PASS** (11/11) | §1 reproduces off CI, on an account that is neither the CI service account nor an administrator — so the §4.2 platform fact about default-owner objects is not masking anything here |
| 2026-08-23 | **P-12** (Low-IL opener) | `LP7760-W1XMP6G3`, `10.0.22631.7517` | **PASS — first execution anywhere** | A genuinely Low-integrity child was refused `ERROR_ACCESS_DENIED`, as predicted. **WP-D4 holds**: the server-side half blocks the only in-scope adversary per [`WINDOWS_WALLET_SUPPORT.md`](WINDOWS_WALLET_SUPPORT.md) §6, and the client-side IL check is not load-bearing alone. Implementation, controls and the negative control in [`WINDOWS_WALLET_PROBE_RESULTS.md`](WINDOWS_WALLET_PROBE_RESULTS.md) §4 |
| 2026-08-23 | P-13 (session separation) | `LP7760-W1XMP6G3` | **UNRUN** | **The blank stays a blank.** Two blockers, and the code one binds first: no P-13 probe exists in the tree at all, and this machine has one interactive session. Not approximated — a single-session stand-in would assert something P-13 does not ask |

**P-12 was refused by the platform default, not by our label.** Recorded here
because it qualifies what the pass means, and kept out of the prediction per
§5. The same descriptor *minus* the mandatory label
(`OwnerOnlyDescriptor::without_label_for_testing` — same owner, same
session-scoped DACL) **also** refused the Low child: the child shares our logon
session so the DACL never blocks it, and an unlabelled object is already Medium
to the OS. This **confirms** `lib.rs`'s standing claim that
`MEDIUM_INTEGRITY_SACL` is "an assertion rather than a gap being closed" —
now observed rather than asserted. Deleting the string would not open the hole
on this build; it is defence-in-depth against a future change to the default,
which is a reason to keep it and a reason to re-run this if that default ever
moves.

**On the probe being an example rather than a `#[test]`.** P-12 needs a real
second process at Low integrity, and `scripts/ci/check_probe_registry.py`
asserts that §2/§3 probes have **no** test function in `tests/probes.rs`. A
`p12_*` test would be a claim that this runs in CI, which §3 pre-declares it
does not — so P-12 stays in §3, the gate stays green, and the runner's
non-`-CiOnly` path is what executes it.

## 5. What a failure does *not* license

Rewriting a prediction to match an observation. If a probe fails, the entry
that changes is the **decision** named in "Revisits on failure", and the
prediction stays on the record as having been wrong. That is the only way this
sheet is worth having written in advance — a pre-registration that gets edited
to match the data is just a lab notebook with extra steps.
