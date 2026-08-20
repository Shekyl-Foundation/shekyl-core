# WINDOWS_WALLET_PROBE_SHEET.md

**Pre-registration for the Windows wallet round (WP).** Written and committed
**before any Windows machine is touched**, and deliberately so.

**Status:** pre-registered 2026-08-19 against `dev` @ `fbd7e770a`. **First run
2026-08-20** on the `Windows (MSVC, daemon)` CI job — 3 passed, 5 failed, and
one prediction was falsified in a way that also exposed a fail-open assertion.
Results in §4. Predictions not yet exercised remain claims about *documented*
behaviour, not observations.

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
| P-4 | Can a *second process* attach an instance to an existing name? | Spawn the helper binary; it attempts `first_pipe_instance(false)` against the parent's pipe | Blocked by the DACL for a different user; **may succeed same-user** | **Nothing** — non-decision-changing per [`WINDOWS_WALLET_SUPPORT.md`](WINDOWS_WALLET_SUPPORT.md) §9.1, since same-user-Medium is out of scope. Recorded because it is cheap and because §9.1 asserts it *cannot matter*, which is a claim worth having evidence against |
| P-5 | Does the peer check return the right owner SID? | Connect client→server in-process, run `PeerCheck::verify` | `Ok` | **WP-D4** — a false negative here makes the wallet unusable; a false positive makes the check theatre |
| P-6 | Does the peer check *refuse* a mismatched SID? | `verify` against a deliberately wrong expected SID | `Err(OwnerMismatch)` | **WP-D4/WP-D5** — this is the bite check. A check that never refuses is the fail-open shape this project has now hit six times |
| P-7 | Is an **unlabelled** pipe read as Medium (a pass)? | Create without a SACL, verify | `Ok` — absence is Medium, not failure | **WP-D4** — if absence reads as failure, every ordinary pipe is refused and the wallet cannot start |
| P-8 | Does the disk probe return sane numbers on a real volume? | `free_bytes_available` on `%TEMP%` | `Ok(n)`, `0 < n <` volume size; and `Err` for a nonexistent path | **WP-D9** — a wrong figure silently disarms the operator-alarm headroom condition |
| P-9 | Does the round-tripped SID match `whoami /user`? | Compare `current_user_sid()` against `whoami /user /fo csv` | Equal | **WP-D1** — the pipe name is derived from this; a wrong SID means the name and the DACL key on different values and self-consistency is lost |

## 2. Deferred to WP-W2/W3 (not yet implementable)

| # | Question | Blocked on | Revisits on failure |
|---|---|---|---|
| P-10 | End-to-end CLI ↔ wallet-rpc over the pipe | WP-W2 transport + WP-W3 peer checks | **WP-Q1** — if axum cannot be driven over create-instance-per-accept without unacceptable complexity, the transport ruling itself is what gets revisited, not the plumbing |
| P-11 | Does a passphrase ever cross the pipe **before** `PeerCheck::verify` returns `Ok`? | WP-W3 | **WP-D3 (2)** — ordering is the whole property; a check that runs after the first write is decoration |

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

---

## 5. What a failure does *not* license

Rewriting a prediction to match an observation. If a probe fails, the entry
that changes is the **decision** named in "Revisits on failure", and the
prediction stays on the record as having been wrong. That is the only way this
sheet is worth having written in advance — a pre-registration that gets edited
to match the data is just a lab notebook with extra steps.
