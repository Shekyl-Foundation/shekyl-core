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

**2026-08-27: three probes now circle one property from three angles, because
two of the three routes proved unavailable on this hardware.** The property is
WP-D6's: the logon SID is unique to its logon session and absent from every
other, so the single logon-SID ACE PR #516 left in the DACL is the whole
session boundary. P-1 and P-15 establish only that the DACL holds exactly that
ACE and that the SID is well-formed; at registration none of the three had yet
tested the *refusal* of a foreign-session caller, which is the claim. **P-17
since has (§4.8): its two-machine run is a structural PASS — a network caller
carries no logon SID, so the ACE refuses it by construction. P-13 and P-18 keep
the terminal-services angle (a genuinely *different* logon SID), still open.**

- **P-17** takes the `IPC$` reachability D6 was written for — the network
  transport. Registered prediction-first (no code in the registering commit).
  Its first runs falsified the loopback premise and then found no single-box
  transport crosses a session (§4.5); a genuine remote same-user caller needed
  domain credentials on a second machine — that machine was provisioned, and
  the two-machine run is now **PASS (structural)** (§4.8): the network-logon
  caller carries *no* logon SID at all, so the logon-SID ACE refuses it by
  construction. (Runs manually with a second box, per §3 — not CI-durable.)
- **P-13** takes terminal-services separation — two concurrent interactive
  logons. **Unachievable on this client SKU** (§4.6): one session per user.
- **P-18** takes a same-user **batch (S4U) logon** — a second logon session
  with no second machine, no network, and no stored credential, opening the
  pipe **locally**. On this hardware it is the *only* runnable route to the
  property, and it isolates the logon-SID ACE most cleanly of the three (a
  local open has no `reject_remote_clients` fence to confound it).

None of the three is superseded or reshaped (§5); each keeps its own prediction
because each produces the foreign-session caller a different way, and which way
is available is a property of the machine.

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
| P-18 | Does the logon-SID ACE refuse a **same-user caller in a different logon session** on a **local** open — WP-D6's load-bearing half, reached without a remote caller or a second interactive session? Registered 2026-08-27 after P-17's transport route and P-13's interactive route both proved unavailable on this hardware | A second logon session as the same user, via an **S4U scheduled task** ("run whether logged on or not / do not store password" → Service-for-User): a new logon SID, the same user SID, **no credential stored anywhere**. Local `\\.\pipe\` open, so S4U's no-outbound-network limitation does not bite. Feasibility (does S4U yield a distinct logon SID for the same user?) is itself measured — the probe asserts it before touching a pipe, the way P-12 asserts its child's integrity level | Four: (a) **control** — a pipe granting the **user SID** is opened by the task process (proves same user, admitted where the user SID is granted); (b) **mechanism** — the task process's token carries our user SID but a **different** logon SID (asserted before any pipe touch — and this "different logon SID" is **correct and transport-scoped**: a *local* S4U session genuinely carries one, unlike a *network*/`IPC$` caller, which carries none at all, §4.8. A phrase-sweep for the premise P-17 falsified must **not** rewrite this row — same words, different transport); (c) **production shape** — the real pipe (logon-SID DACL + label) refuses it; (d) **the D6 claim proper** — a pipe with the logon-SID DACL and **no label** still refuses it with `ERROR_ACCESS_DENIED`, isolating the ACE (no `reject_remote_clients` confound, because a local open is not remote) | **WP-D6** — if **(d)** admits the task process, the logon-SID ACE does not carry the session boundary and PR #516's user-SID removal bought nothing. If (b) shows the same logon SID (S4U did not cross), the probe is **UNRUN**, not a pass. This is the runnable route to the property P-17 (network) and P-13 (interactive) each reach differently — and, on this hardware, the *only* runnable one |
| P-17 | Does the logon SID **by itself** refuse a caller from a different logon session — the `IPC$` reachability WP-D6 exists for? Registered 2026-08-27, **corrected the same day before any run** (see below: production carries a second fence the design doc never recorded) | Needs a loopback SMB path (`LanmanServer` + the `IPC$` share) to produce a network logon. Whether the CI runner has one is **unverified**, and asserting either way is the defect class §5 is written against. Reports UNRUN when the precondition is absent — never a pass | Four, and the fourth is the one that attributes the result: (a) **control** — the pipe opens locally via `\\.\pipe\…`, proving it works and the DACL admits us; (b) **mechanism** — a caller arriving over loopback carries a logon SID *different* from `current_logon_sid()`; (c) **production shape** — a pipe built exactly as `create_instance` builds it (owner-only DACL **and** `reject_remote_clients(true)`) refuses the loopback open; (d) **the D6 claim proper** — a pipe with the same owner-only DACL but `reject_remote_clients(**false**)` *still* refuses it, with `ERROR_ACCESS_DENIED`. Only (d) isolates the logon SID | **WP-D6** — if **(d)** succeeds, the logon SID does not carry the `IPC$` boundary on its own, removing the user-SID ACE in PR #516 bought nothing on that axis, and the flag is load-bearing where the doc says the SID is. If **(c)** succeeds, production itself is reachable over `IPC$` and that is a live hole rather than a documentation one. If no transport crosses (b), the probe is **UNRUN**, not a pass, and — per the 2026-08-27 first run, §4.5 — this revisits **P-17's method** rather than WP-D6: loopback reuses the caller's token, so the question needs a genuinely remote caller, and the `reject_remote_clients` fence stays untested until one exists. **2026-08-28, §4.8:** the genuinely remote caller arrived — and the method needed re-working again, because a network logon carries *no* logon SID at all, so row (d) is answered structurally rather than by a different-SID comparison |

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

**What the session boundary does *not* mean — precluding the first misreading.**
A user who remotes into their own machine and runs the wallet there is **fully
supported, by construction**. The Windows wallet is self-hosted per session:
`shekyl-cli` spawns its in-process server and dials its own pipe, so client and
server are born in the *same* logon session and share a logon SID as siblings —
an RDP logon gets a fresh logon SID and the wallet pair started inside it
shares that one. The boundary refuses only a *cross-session* attach: a process
in session A opening a pipe created in session B — which, with no external
`npipe://` form (§8.1), is not a supported operation whose loss costs anything.
The positive case needs no probe: it is structural, and P-5 already exercises
the in-session open-and-verify. If a user's console wallet is still open when
they try to start one over RDP, what refuses them is the **keys-file lock**
(`AlreadyLocked`, "wallet is already open elsewhere") — the same behaviour as
two terminals on Linux — not the pipe DACL.

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

### 4.5 P-17 first run (2026-08-27): the premise was false, and it was the *method* not WP-D6

`LP7760-W1XMP6G3`, Windows 11 23H2 `10.0.22631.7517`, at `19b379c37`.

| Date | Probe | Machine / build | Result | Consequence |
|---|---|---|---|---|
| 2026-08-27 | P-17 row (b) | `LP7760-W1XMP6G3`, `10.0.22631.7517` | **FALSIFIED** — the `\\localhost\pipe\…` caller carried **our** logon SID (`S-1-5-5-0-43722672`) | See below. Rows (a), (c), (d) did not run — the probe returns at (b) rather than measuring a local open wearing a remote name |

**What was measured, and how carefully.** The loopback caller's logon SID was
identical to ours, verified two ways by the runner — `current_logon_sid()` and
a scratch binary both returned `S-1-5-5-0-43722672`, matching what the server
read off the impersonation token — and `remote_form`'s rewrite to
`\\localhost\pipe\…` was confirmed real, so this is not a probe quietly dialling
the local path. `LanmanServer` is running, `IPC$` present, the connection
**succeeded**, and impersonation worked. The transport is functional; it simply
does not cross a session.

**This is §4.1's shape, not a WP-D6 falsification — the distinction is
load-bearing.** What broke is the *premise* "loopback SMB produces a distinct
logon session": a loopback caller reuses its own token, so it **is** us, in our
session. The DACL admitting it is correct behaviour, not a hole. WP-D6's claim
is about a caller in a *different* logon session, and P-17 has said nothing
about that caller yet. Exactly as P-1's first run failed on SDDL canonicalisation
while the descriptor was correct all along, here the method was wrong and the
policy is untouched. Per §5 the row-(b) prediction stays on record as
falsified; what changes is the consequence — it revisits **P-17's method**, and
the second fence (`reject_remote_clients`) remains equally untested, since
nothing in this run was a remote client.

**Re-method (same commit family).** The probe now tries each host in
`transport_hosts()` — `localhost` (known not to cross, kept as the recorded
control) and the machine's own name (a candidate that *might* take the
network-provider path into a network logon; **measured, not asserted**). Only a
host whose caller SID differs from ours is used for the attribution rows; if
none crosses, the verdict is **UNRUN** with "needs a genuinely remote caller."

**Second run (2026-08-27, `4c31c518a`): the machine-name form does not cross
either — the cheap route is closed.**

| Date | Probe | Machine / build | Result | Consequence |
|---|---|---|---|---|
| 2026-08-27 | P-17, both single-box transports | `LP7760-W1XMP6G3`, `10.0.22631.7517` | **UNRUN** | `\\localhost\pipe\` **and** `\\LP7760-W1XMP6G3\pipe\` both carried `S-1-5-5-0-43722672` — our SID, byte-for-byte. The machine-name form **connected and impersonated** (no NTLM-loopback refusal, no `ERROR_ACCESS_DENIED`); it simply short-circuits to the same local token. No single-box SMB path on this build crosses a logon-session boundary |

**What this settles.** The free experiment — can one box pose as a foreign
session over its own name? — is answered **no**, and answered by measurement
rather than left as an untried maybe. WP-D6's `IPC$` claim, and the
`reject_remote_clients` fence, are therefore reachable only by a **genuinely
remote caller**: a second host on the subnet dialling
`\\LP7760-W1XMP6G3\pipe\…`, or a VM with its own logon session. That is a
machine to provision, not a code change — and the decision it informs is
WP-D6's reason for existing, currently tested by nothing.

### 4.6 P-13: the platform will not provide the precondition (2026-08-27)

| Date | Probe | Machine / build | Result | Consequence |
|---|---|---|---|---|
| 2026-08-27 | P-13 (terminal-services session separation) | `LP7760-W1XMP6G3`, `10.0.22631.7517` | **UNACHIEVABLE HERE** — not merely unrun | This is a **client SKU** (`ProductType = 1`) with `fSingleSessionPerUser = 1`. A second interactive logon as the same user **takes over** the first rather than running concurrently, so "two concurrent interactive logons" cannot exist for one user without third-party session patching — which has no place near a security probe. The `rdp-tcp` listener being up (reported earlier) is necessary and not sufficient |

**Recorded as a platform fact, not a backlog item.** P-13 stays registered and
its prediction stands (§5); what has changed is that its precondition is
**provably unavailable on this hardware**, which is a §3 result rather than an
open TODO. The underlying property P-13 was to test — the logon SID separating
sessions — is reached instead by **P-18** through an S4U batch logon, which does
not need a second interactive session. P-13 reopens only on a machine (a
Windows Server SKU, or a client with multi-session explicitly and legitimately
enabled) where concurrent interactive logons are a supported configuration.

**Now confirmed across two client generations (2026-08-29).** The P-17
two-machine run's caller, `DTASUS-Z970`, is **Windows 11 Enterprise 25H2**
(`10.0.26200`), `InstallationType = Client` — two releases newer than `LP-1`'s
23H2 (`10.0.22631`). Both are client SKUs, so P-13's "unachievable on a client
SKU" is not a quirk of one build: the single-session-per-user constraint holds
across the two generations we have measured, which is a stronger statement than
either box could make alone. It reopens on a Server SKU or an explicitly
multi-session client, as above — not on a newer client release.

### 4.7 P-17 two-machine harness, local dry-run (2026-08-27, `edd471767`)

Ran `--serve` and the real `p17_remote_dial.ps1` client against it in **one
session** on `LP7760-W1XMP6G3`, before the second machine existed. It settled
three things and measured a fourth that was not supposed to be reachable here.

| Date | Observation | Result | Consequence |
|---|---|---|---|
| 2026-08-27 | The accept + impersonation + report protocol | **WORKS** | The accept thread's `ConnectNamedPipe` returns, the raw-handle move into the thread survives, the server reads *both* the caller's user and logon SID off the impersonation token, and the control-pipe write/read round-trips. None had executed before |
| 2026-08-27 | The same-user/**same-session** guard | **HOLDS** | Presented with a same-session caller (logon SID `S-1-5-5-0-43722672` = the server's), the server printed `UNRUN: did not cross`, **not** a PASS. A false PASS here was the worst available failure; it is ruled out by observation, not by reading the code |
| 2026-08-27 | **`reject_remote_clients`, isolated** | **VERIFIED, single box** | Same caller, same session, same instant, both pipes dialled over the same `\\HOST\pipe\` path: `daclonly` (no flag) **opened** (os 0), `prod` (flag) **refused** (os 5). The only difference is the flag, so it refuses a `\\HOST\pipe\` dial by the **path form**, not by whether the caller genuinely crossed a machine boundary. One of WP-D6's two fences, measured for the first time — and it did **not** need the second machine |

**Correction to a claim made earlier in this round.** The two-machine mode was
described as "what exercises the `reject_remote_clients` fence, which no
single-box route could reach." The dry-run reached it: the flag keys on the
path, so a same-box `\\HOST\pipe\` dial triggers it. What genuinely needs the
second machine is **row (d) alone** — the logon-SID ACE. `prod` will refuse a
remote caller too, but the dry-run now proves that tells us about the *flag*,
so only the DACL-only pipe (no flag) can attribute a refusal to the ACE, and
only a caller that truly crosses a session can be refused by it. That caller is
the one thing a single box cannot produce (§4.5, §4.6).

### 4.8 P-17 two-machine run — PASS: the cross-session caller carries *no* logon SID (2026-08-28, `ffe836cd7` → `5e459919b`)

The second machine — `DTASUS-Z970`, domain-joined, logged in as the **same AD
user** (`intranet\dawsonra`, `S-1-5-21-…-1108`) — dialled
`\\LP7760-W1XMP6G3\pipe\…` over `IPC$`. For the first time a genuinely remote,
same-user caller reached the server. The result is not (c), not (d) as
written, but a **third outcome that relocates the whole question**.

| Date | Machine / build | Result | What the server logged |
|---|---|---|---|
| 2026-08-28 15:45:48 -04:00 | server `LP7760-W1XMP6G3` (pid 83536, `ffe836cd7`); caller `DTASUS-Z970`, same AD user, over SMB | **UNRUN — with diagnosis** | The caller **connected, its report was read, and impersonation succeeded** (each of those failures has its own distinct message; none fired). What failed is one step later and narrower: reading a SID off the impersonation token we successfully held. Client-side, the dial reported `daclonly -> 5`, `prod -> 5` (the `5 5` "PASS shape"); server-side, the token yielded no usable SID pair |

**This is §4.1's shape, not a WP-D6 falsification — and it is a stronger result
than row (d) was built to get.** What broke is the row-(d) *method's* premise:
"a caller in a different logon session carries a **readable, different** logon
SID," which the verdict compared against `current_logon_sid()`. A **network
(`IPC$`) logon does not**. `logon_sid_of` walks `TokenGroups` for a
`SE_GROUP_LOGON_ID`-marked group of `S-1-5-5-…` shape and returns
`SidError::NoLogonSid` when none is present (`sid.rs`) — and the crate's own doc
that "every interactive and service logon has one" is pointedly silent on
*network*. Per §5 the row-(b)/(d) prediction stays on record as falsified in its
method; what changes is the consequence — it revisits **P-17's method**, again,
not WP-D6's policy.

**Why the collapsed message could not yet name it, and the fix.** The verdict's
`_ =>` arm folded *user-SID read failed* and *logon-SID read failed* into one
string, and the channel dropped the caller's `5 5` on every non-success path —
so the log recorded a bare "could not read … SID" with no codes, and the `5 5`
survived only in the caller's own stdout. The same defect class this round has
hunted repeatedly: a message naming two possibilities and distinguishing
neither. The probe is now split (same commit): the arm reports **which** side
failed and the `SidError` **variant** (`{:?}`, never Display — Display's
`TokenGroups` text still says "user SID"), and every post-report path carries
`dacl_err`/`prod_err`. A new verdict case, `UserOkNoLogon`, is pre-wired for the
outcome below so the re-run is conclusive whichever way it lands.

**Amended prediction (pre-registered before the re-run, at `ffe836cd7`).** The
split re-run will report the caller as **user `S-1-5-21-…-1108`, logon
`NoLogonSid`**; if `daclonly` is refused with `ERROR_ACCESS_DENIED`, that is
**P-17 PASS (structural)**. Stated precisely (the variant carries it): "the
caller's token has no `SE_GROUP_LOGON_ID`-marked group of logon-SID shape,"
not the flatter "network logons have no logon SID."

**Confirmed (2026-08-28 16:25:38 -04:00, server `5e459919b`).** One synchronous
dial from `DTASUS-Z970` — machine `DT-1`, **Windows 11 Enterprise 25H2**
(`10.0.26200`), a client SKU **two releases newer** than `LP-1`'s 23H2
(`10.0.22631`) — same AD user, no poller before it. That the two machines are
two generations apart makes the structural PASS **independent confirmation** on a
newer client SKU rather than a re-run of the box that produced P-1…P-16, and it
is why the P-13 client-SKU ruling now holds across both (§4.6):

| Date | Machine / build | Result | Verdict |
|---|---|---|---|
| 2026-08-28 16:25:38 -04:00 | server `LP7760-W1XMP6G3` (pid 84880, `5e459919b`); caller `DTASUS-Z970`, same AD user (`…-1108`), over `IPC$` | **PASS (structural)** | `SidTriage::UserOkNoLogon` = `(Ok(user …-1108), Err(SidError::NoLogonSid))`; daclonly `5`, prod `5`. The impersonation token carried the **user** SID but **no** logon-SID-shaped `SE_GROUP_LOGON_ID` group, so the logon-SID-only ACE could not match it and refused with `ERROR_ACCESS_DENIED` |

The result is **self-attributing**, which is what makes it evidence rather than
coincidence: the very token that lacked a logon SID *did* carry the user SID
`…-1108`, so a user-SID ACE would have admitted this caller. That counterfactual
is not a bare assertion — §4.7's single-box dry-run is its **positive control**:
the DACL-only pipe *admitted* (os 0) a caller whose token **did** hold the
granted SID. So *admits-when-the-token-matches* (§4.7) and *this token carries
the user SID* (here) together pin the refusal on the one thing that differs
between the two descriptors — and PR #516's removal of the user-SID grant is
exactly what carries the boundary. `prod`'s `5` is over-determined (both fences
apply); `daclonly`'s `5`, carrying no flag, is the clean attribution.

**Scope of what this measures — the `IPC$`/remote-reachability axis only.** The
`reject_remote_clients` fence was measured by path form (§4.7); the
logon-SID-only ACE is measured here, by a genuine `IPC$` caller's **absence of
the class the ACE grants to**. WP-D6's *other* half — **terminal-services
separation**, a same-user caller in a genuinely *different* logon session
refused by the verdict's `Both`-arm PASS — was **not** exercised here: that arm
has fired for nobody, and is kept live precisely for it. It remains **P-13**'s
(interactive) and **P-18**'s (S4U) question; this run does not retire them. Row
(d)'s `IPC$` form is answered, and answered more strongly than it was posed: not
"your session isn't ours" (defeatable by a colliding value, dependent on session
bookkeeping) but "you hold nothing in the granted class."

**§5, explicitly.** The pre-registered prediction was a *different* logon SID;
the observation is *no* logon SID. Per §5 that prediction stays on record as
wrong **in form** — the P-1 §4.1 shape once more — while the decision it
guarded (keep the logon-SID-only ACE; PR #516's user-SID removal is
load-bearing) is **upheld, on stronger ground** than the prediction assumed.
The PASS is not "we called it"; it is "we predicted the right decision, for a
reason that turned out to be understated."

**Design consequence, now due (confirmed) — landed in this commit family.** The
`sid.rs` docs that a logon SID is something "every interactive and service logon
has" now name the network case and warn that `NoLogonSid` is the WP-D6
*mechanism*, not a "shouldn't happen" to be papered over with a user-SID
fallback — which would silently undo D6 again. `WINDOWS_WALLET_SUPPORT.md`'s
WP-D6 rationale gains the structural sentence: the `IPC$` boundary holds not
because a remote session has a *different* logon SID but because it has *none*,
so a logon-SID-scoped descriptor is unmatchable from the network by
construction.

**Harness bite-checked (2026-08-28), because a broken gate looks like a passing
one.** Two runner fixes on this branch were verified by making them fire, not by
reading them:

- *Rule 47 — build-error vs UNRUN.* A syntax error injected into the p12 example
  made `cargo run` exit 101; the runner reported **FAIL, exit 1**, where the
  prior `default => UNRUN` mapping would have printed a benign non-measurement
  under "No probe FAILED." CI exercises only P-17's identical mapping — `-CiOnly`
  skips P-12 — which is now noted at the skip site.
- *`mechanism_row`'s 30 s timeout — the detach fix.* Calibrated first, because
  the obvious test cannot discriminate: an RFC 5737 TEST-NET-1 host
  (`192.0.2.1`) fails the SMB connect at **~26.7 s** — *before* the 30 s bound,
  so it would never fire the timeout and a "verified" off it would be false; an
  in-subnet ARP-hole (`10.10.12.253`) stalls to **~31.2 s** and does. Injected as
  the first `transport_hosts()` entry, the run took the `recv_timeout` arm
  (confirmed by its distinct "did not measure … reported nothing within 30s"
  message, since **30.3 s** wall against **31.2 s** stall is inside timing
  noise), and — the point of the detach — **continued** to the next host and
  produced a verdict rather than blocking for the OS's full connect duration on
  the stall (and, on a host that never returns, forever). A `join()` that defeats
  its own timeout is invisible to compile, clippy and CI alike until something
  stalls; the calibration is what made the check a check.

## 5. What a failure does *not* license

Rewriting a prediction to match an observation. If a probe fails, the entry
that changes is the **decision** named in "Revisits on failure", and the
prediction stays on the record as having been wrong. That is the only way this
sheet is worth having written in advance — a pre-registration that gets edited
to match the data is just a lab notebook with extra steps.
