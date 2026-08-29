# WINDOWS_WALLET_PROBE_RESULTS.md

**Raw run log for the Windows wallet round (WP).** One row per probe per
machine, with the toolchain and OS build that produced it.

**This file is not the decision record.**
[`WINDOWS_WALLET_PROBE_SHEET.md`](WINDOWS_WALLET_PROBE_SHEET.md) §4 is, and it
stays canonical: the sheet is the pre-registration, it names which decision a
failure revisits, and §5 forbids editing a prediction to match an observation.
This file exists because §4 records *consequences* — one line per result,
written for a reader deciding whether WP-D4 still holds — and a machine-level
run log has different content: exact exit codes, the controls that ran, the
toolchain, what was left unrun and why.

Keep them from drifting the way two copies always do: **§4 is written from this
file, never the reverse.** If they disagree, this file is the observation and
§4 is the reading of it — fix §4's reading, not this file's numbers.

---

## 1. Machines

| Tag | Machine | OS | Toolchain | Session |
|---|---|---|---|---|
| `CI` | `windows-2025-vs2026` | GitHub-hosted | per workflow | service account, no interactive logon |
| `LP-1` | `LP7760-W1XMP6G3` | Windows 11 Enterprise 23H2, `10.0.22631.7517` (`OSVersion.Version` = `10.0.22631.0`) | `rustc 1.94.0 (4a4ef493e 2026-03-02)`, `x86_64-pc-windows-msvc`, pinned by `rust-toolchain`; host default is 1.95.0 | **one** console session (ID 1), Medium integrity, **not** elevated |
| `DT-1` | `DTASUS-Z970` | domain-joined Windows, same AD domain as `LP-1` | none — .NET `NamedPipeClientStream` only; it is the P-17 *caller*, not a runner | interactive logon as the **same AD user** as the server |

`LP-1` is the first machine with an interactive logon to run this sheet, which
is what §3 was waiting for.

---

## 2. Runs

| Run | Date | Tag | Tree | Runner |
|---|---|---|---|---|
| A | 2026-08-20 | `LP-1` | PR #523 @ `c83a2b740` | `windows_probe.ps1`, no `-CiOnly` |
| B | 2026-08-23 | `LP-1` | PR #523 @ `3382daa2c` | `windows_probe.ps1`, no `-CiOnly` |
| C | 2026-08-23 | `LP-1` | `dev` @ `4a76f490a` + the uncommitted P-12 work below | `windows_probe.ps1`, no `-CiOnly` |
| D | 2026-08-28 | `LP-1` + `DT-1` | `feat/wp-p17-ipc-logon-sid-probe` @ `fa67b5097` | two-machine P-17: `LP-1` runs the probe `--serve`, `DT-1` runs `p17_remote_dial.ps1` as the same AD user |

Runs A and B are the same measurement: the only diff between those two trees is
`WINDOWS_WALLET_SUPPORT.md` (+116 lines, the WP-W2 preamble). Run B is recorded
anyway because a re-measurement that was *predicted* to be identical and was
identical is worth more on the record than an assumption.

---

## 3. Results

`PASS`/`FAIL` are verdicts against the sheet's prediction. **`UNRUN` is not a
near-pass** — it means nothing was measured, per §0.

| Probe | A | B | C | Note |
|---|---|---|---|---|
| P-1 SDDL round-trip | PASS | PASS | PASS | the structurally-rebuilt form from §4.1 |
| P-2 protected DACL | PASS | PASS | PASS | |
| P-3 first-instance refusal | PASS | PASS | PASS | the §4 reactor defect does not reproduce |
| P-4 second-process attach | UNRUN | UNRUN | UNRUN | §2: deliberately not implemented; revisits **Nothing** |
| P-5 peer check accepts | PASS | PASS | PASS | |
| P-6 peer check refuses | PASS | PASS | PASS | |
| P-7 unlabelled reads Medium | PASS | PASS | PASS | the §4.2 owner fix holds on a non-admin account |
| P-8 disk probe | PASS | PASS | PASS | |
| P-9 user SID | PASS | PASS | PASS | |
| P-9-ext `whoami` cross-check | PASS | PASS | PASS | see §5.1 — it failed once, for a reason that was not the machine's |
| P-10 CLI ↔ wallet-rpc e2e | UNRUN | UNRUN | UNRUN | not driven by this runner. **Not "never run"** — the sheet §4.3 records the wallet-rpc half passing in CI on 2026-08-21 via the scouting step; the cli half is still unobserved |
| P-11 passphrase ordering | UNRUN | UNRUN | UNRUN | §2: blocked on WP-W3 |
| **P-12 Low-IL opener** | UNRUN | UNRUN | **PASS** | **first run anywhere.** §4 below |
| P-13 session separation | UNRUN | UNRUN | UNRUN | **never run anywhere.** §6 below |
| P-14 truncated label ACE | PASS | PASS | PASS | absent at `9563b4e1`; restored by `c83a2b740` |
| P-15 logon SID shape | PASS | PASS | PASS | |
| P-16 seed file owner-only | — | — | PASS | not present on the PR #523 tree; landed on `dev` |
| **P-17 IPC\$ logon-SID refusal** | — | — | — | not in runs A–C (registered after C). **Run D (two-machine): PASS (structural)** — a genuine remote same-user caller carries **no** logon SID, so the ACE refuses it by construction; full analysis in the sheet §4.8. Single-box §4.5 found no crossing transport |
| P-18 batch (S4U) logon | — | — | — | registered 2026-08-27; **unrun** — the runnable local route to the same property (sheet §3) |

Runner exit: A `0`, B `0`, C `0`; run D's server exited `0` (P-17 verdict
`P-17 PASS (structural)`, sheet §4.8). `check_probe_registry.py` clean on every
single-box run (C: *"11 CI-durable probes registered and implemented … 5
deferred/laptop-only, correctly unimplemented"*).

---

## 4. P-12 — first result, and it matches the prediction

**PASS on `LP-1`, 2026-08-23.** A genuinely Low-integrity child process was
refused with `ERROR_ACCESS_DENIED` (5), which is exactly what §3 predicted.
**WP-D4's server-side half blocks the only in-scope adversary per
`WINDOWS_WALLET_SUPPORT.md` §6.** Nothing is revisited.

Implemented as `rust/shekyl-win-sec/examples/p12_low_il_probe.rs`, driven by the
runner's non-`-CiOnly` path. An **example, not a `#[test]`**, for two reasons:
it needs a real second process at Low integrity, and `check_probe_registry.py`
asserts §2/§3 probes have no test function in `tests/probes.rs` — a `p12_*`
test would be a claim that this runs in CI, which §3 pre-declares it does not.

### 4.1 What was established before the verdict was believed

§4.2 of the sheet records P-7 failing because it never reached the path it
existed to test. A Low-IL child that fails to open a pipe for an unrelated
reason looks identical to a pass, so three things are checked first:

1. **The pipe is openable.** The parent opens it in-process at Medium.
   Observed: *"a Medium in-process opener reaches the pipe (as expected)"*.
2. **The child ran.** It reports through its exit code; a child that never
   started yields a code that is neither `0` nor a plausible `CreateFile`
   error, and is reported `UNRUN`.
3. **The child was actually Low.** It reads its own token's integrity level and
   refuses to continue unless it is `S-1-16-4096`.

### 4.2 The check was made to fail on purpose

Per `50-testing`'s every-check-must-be-able-to-fail discipline, and because a
probe that has never gone red is indistinguishable from one that cannot:
flipping the single argument `low_il: true` → `false` at the spawn site — the
spawn path is otherwise identical for both children — produced

```text
P-12 UNRUN: the child was not at Low integrity, so the label was never the
thing under test. Not a pass.
```

The guard fired rather than the probe passing quietly, which is the behaviour
that makes the `PASS` above worth anything. Reverted immediately; the flip was
never committed.

### 4.3 The refusal is the platform's, not our SDDL string

Recorded as a supplementary observation, deliberately **outside** the verdict —
§5 forbids folding a new observation into a pre-registered prediction.

The same descriptor **minus** the mandatory label
(`OwnerOnlyDescriptor::without_label_for_testing` — same owner, same
session-scoped DACL) **also refused the Low child with
`ERROR_ACCESS_DENIED`.** The Low child shares our logon session, so the DACL
does not block it; what blocks it is integrity. But an unlabelled object is
already Medium to the OS, so the block is the platform default rather than our
explicit `(ML;;NW;;;ME)`.

This **confirms** what `lib.rs` already claims — that the label is "an
assertion rather than a gap being closed" — and it is now observed rather than
asserted. The operational reading: on this Windows build, deleting
`MEDIUM_INTEGRITY_SACL` would not open the hole, so the string is
defence-in-depth against a future default change, not the thing doing the work.
That is worth knowing before someone deletes it as redundant, and worth
re-checking if Windows ever changes the default label for unlabelled objects.

---

## 5. Findings that are not probe verdicts

### 5.1 P-9-ext failed once, and the cause was the shell, not the machine

Run A first executed the runner through Git Bash, which puts `/usr/bin/whoami`
(coreutils) ahead of `C:\Windows\System32\whoami.exe`. The runner's
`whoami /user /fo csv` was parsed by coreutils, which rejected `/user` as an
extra operand, so `$whoami` was empty and the comparison failed:

```text
P-9-ext  FAIL  crate said 'S-1-5-21-…-1108', whoami said ''
```

Re-run from native PowerShell: `PASS`. Recorded rather than discarded for two
reasons. It **failed closed**, which is the correct direction and is evidence
the check can fail. And it is a real portability edge for anyone running this
sheet from a POSIX-flavoured shell on Windows — the runner assumes Windows
`PATH` resolution and does not state so.

### 5.2 P-4 and P-14 both went missing without anything noticing

Not observed on `LP-1` — both predate these runs — but they are the reason
`check_probe_registry.py` exists, and it is clean on every run above. Noted
here so the run log carries why that gate is in the loop.

---

## 6. P-13 is still unrun, on every machine

**Left deliberately blank. A blank is a finding (§3's recording protocol).**

P-13 needs two *concurrent* interactive logons. `LP-1` has one:

```text
 SESSIONNAME       USERNAME     ID  STATE   TYPE   DEVICE
 services                        0  Disc
>console           dawsonra      1  Active
 rdp-tcp                     65536  Listen
```

Session 0 is the non-interactive services session, not a second logon. It was
not approximated with a single-session stand-in, because a stand-in would be
asserting something P-13 does not ask.

**Two separate blockers, and the code one binds first:**

1. **No implementation.** There is no P-13 probe anywhere in the tree. Until
   one exists, no environment produces a result.
2. **One session.** The `rdp-tcp` listener is up as of 2026-08-23, so a second
   concurrent session is *obtainable* here via RDP loopback — this blocker is
   no longer the binding one, but it is not yet cleared either.

When P-13 is implemented it will need the same treatment P-12 got: a control
proving the pipe is reachable from the *first* session, so that a second
session's refusal is attributable to the logon SID rather than to anything else
about the second session.

---

## 7. What this run does not license

The same thing §5 of the sheet says. P-12 passing does not retire WP-D4's
client-side integrity check: `PeerCheck` guards the *client* against a hostile
server, and P-12 measured the *server's* label against a hostile client. They
are different directions and both halves are still load-bearing.
