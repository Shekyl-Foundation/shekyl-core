# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

<#
.SYNOPSIS
    Runs the pre-registered Windows probes for the WP round.

.DESCRIPTION
    One entry point for both the laptop and CI, so the two cannot drift into
    "works on my machine". Output is exit codes and a table keyed by probe id;
    nothing here needs to be summarised in prose to be actionable.

    Pre-registration lives in docs/design/WINDOWS_WALLET_PROBE_SHEET.md. Each
    probe there names the DECISION a failure revisits — this script does not
    repeat that, deliberately, so there is one place to edit.

.PARAMETER CiOnly
    Skip the probes §3 pre-declares as needing an interactive logon (P-12,
    P-13). CI passes this. It is a switch rather than auto-detection so that a
    CI run cannot silently skip more than was pre-registered.

.EXAMPLE
    pwsh scripts/ci/windows_probe.ps1
    pwsh scripts/ci/windows_probe.ps1 -CiOnly
#>
[CmdletBinding()]
param(
    [switch]$CiOnly
)

$ErrorActionPreference = 'Stop'

# A non-zero exit from the commands below is DATA, not an error: `cargo test`
# exits non-zero when a probe FAILS, and the P-12 example exits 1 for FAIL and 2
# for UNRUN. Every one of those is a verdict this script exists to record.
#
# `$PSNativeCommandUseErrorActionPreference` promotes a native command's
# non-zero exit into a terminating error under `$ErrorActionPreference = 'Stop'`
# — before `$LASTEXITCODE` can be read. A host with it enabled would abort this
# script mid-run and print no summary table at all, so a FAIL or UNRUN would be
# LESS visible than a pass: the reporting would work exactly when there is
# nothing to report and break when there is.
#
# **Measured, because the conditional above is doing real work.** On the pwsh we
# actually run (7.6.5) the preference defaults to `False`, and
# `$ErrorActionPreference = 'Stop'` alone does **not** turn it on — a native
# `exit 3` is reached with `$LASTEXITCODE = 3`. So this line is not fixing a
# live abort here; it makes the script immune to a host that has the preference
# on, which is a profile, a policy, an older 7.3/7.4 default, or a future
# change to it. The failure path itself is now observed rather than assumed: a
# deliberately failed §1 probe prints the table, carries the exit code in the
# FAIL row, lets §3 still report, and exits 1.
#
# Script-scoped rather than wrapped around each call, because it is true of
# every native invocation here — there is no command in this file whose
# non-zero exit should abort the run. Assigning it on a PowerShell that has no
# such preference is harmless.
$PSNativeCommandUseErrorActionPreference = $false

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$results = [System.Collections.ArrayList]::new()
$failed = 0

function Add-Result {
    param($Id, $Status, $Detail)
    [void]$results.Add([pscustomobject]@{ Probe = $Id; Status = $Status; Detail = $Detail })
    if ($Status -eq 'FAIL') { $script:failed++ }
}

# ---------------------------------------------------------------------------
# §1 — the CI-durable probes, as Rust tests.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '== SECTION 1: CI-durable probes (cargo test) ==' -ForegroundColor Cyan

Push-Location (Join-Path $repo 'rust')
try {
    # `--features test-utils` for P-6's mismatched-SID constructor. Exit code
    # is read directly, never through a pipe (rule 46).
    cargo test --locked -p shekyl-win-sec --features test-utils --test probes -- --nocapture
    $cargoExit = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($cargoExit -eq 0) {
    Add-Result 'P-1,2,3,5,6,7,8,9,14,15,16' 'PASS' 'cargo test -p shekyl-win-sec --test probes'
} else {
    Add-Result 'P-1,2,3,5,6,7,8,9,14,15,16' 'FAIL' "cargo exited $cargoExit — see output above; the sheet names which decision each revisits"
}

# P-9's external half: the crate's own SID must match what the OS reports.
# Done here rather than in the test because a unit test shelling out to verify
# its own subject is circular.
Write-Host ''
Write-Host '-- P-9 external cross-check (whoami) --'
try {
    $whoami = (whoami /user /fo csv | ConvertFrom-Csv).SID
    Push-Location (Join-Path $repo 'rust')
    try {
        $printed = cargo run --locked -q -p shekyl-win-sec --features test-utils --example print_sid 2>$null
        $runExit = $LASTEXITCODE
    } finally { Pop-Location }

    if ($runExit -ne 0 -or [string]::IsNullOrWhiteSpace($printed)) {
        Add-Result 'P-9-ext' 'FAIL' 'could not read the SID from the crate'
    } elseif ($printed.Trim() -eq $whoami) {
        Add-Result 'P-9-ext' 'PASS' "crate and whoami agree: $whoami"
    } else {
        Add-Result 'P-9-ext' 'FAIL' "crate said '$($printed.Trim())', whoami said '$whoami' — WP-D1's name and DACL would key on different values"
    }
} catch {
    Add-Result 'P-9-ext' 'FAIL' "cross-check errored: $_"
}

# ---------------------------------------------------------------------------
# §3 — laptop-only. PRE-DECLARED as CI-fragile in the sheet, not discovered to
# be. Skipping is explicit and reported, never silent.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '== SECTION 3: interactive-logon probes ==' -ForegroundColor Cyan

if ($CiOnly) {
    Add-Result 'P-12' 'SKIP' 'pre-declared laptop-only (needs a genuine Low-IL process)'
    Add-Result 'P-13' 'SKIP' 'pre-declared laptop-only (needs two interactive logons)'
    Write-Host 'Skipped by -CiOnly, as pre-registered in the sheet §3.' -ForegroundColor Yellow
} else {
    # P-12: does the Medium mandatory label block a Low-IL opener?
    #
    # An EXAMPLE rather than a `#[test]`, for two reasons the example's own
    # module docs give in full: it needs a genuine second process at Low
    # integrity, and check_probe_registry.py asserts that §3 probes have no
    # test function in tests/probes.rs — a `p12_*` test would be a claim that
    # this runs in CI, which §3 pre-declares it does not.
    #
    # The example carries its own controls (a Medium opener must reach the
    # pipe; the child must confirm its own integrity level before it opens
    # anything), so a refusal for an unrelated reason reports UNRUN rather
    # than passing quietly.
    Write-Host ''
    Write-Host '-- P-12: does the Medium label block a Low-IL opener? --'
    Push-Location (Join-Path $repo 'rust')
    try {
        cargo run --locked -q -p shekyl-win-sec --features test-utils --example p12_low_il_probe
        $p12Exit = $LASTEXITCODE
    } finally { Pop-Location }

    switch ($p12Exit) {
        0 { Add-Result 'P-12' 'PASS' 'Low-IL open refused with ERROR_ACCESS_DENIED, as predicted' }
        1 { Add-Result 'P-12' 'FAIL' 'see output above; per the sheet this revisits WP-D4, not the probe' }
        default { Add-Result 'P-12' 'UNRUN' "the probe could not measure the label (exit $p12Exit) — not a pass" }
    }

    # P-13 needs two CONCURRENT interactive logons, which one console session
    # cannot provide. Left unrun rather than approximated: a single-session
    # stand-in would be asserting something P-13 does not ask.
    Add-Result 'P-13' 'TODO' 'needs two concurrent interactive logons — manual, result goes in the sheet §4'
}

# ---------------------------------------------------------------------------
# P-17 — the IPC$ half of WP-D6. Runs in BOTH modes: its precondition is a
# loopback SMB path (`LanmanServer` / the `IPC$` share), not an interactive
# logon, and whether the runner has one is the §3.1 promotion question. The
# probe detects that precondition itself and reports UNRUN when it is absent,
# so it is safe to run unconditionally — exit 2 is a reportable outcome, never
# a pass, and never a hard failure of the run.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '-- P-17: does the logon SID alone refuse a cross-session (IPC$) caller? --'
Push-Location (Join-Path $repo 'rust')
try {
    cargo run --locked -q -p shekyl-win-sec --features test-utils --example p17_ipc_logon_sid_probe
    $p17Exit = $LASTEXITCODE
} finally { Pop-Location }

switch ($p17Exit) {
    0 { Add-Result 'P-17' 'PASS' 'the logon-SID ACE alone refused a loopback caller with ERROR_ACCESS_DENIED' }
    1 { Add-Result 'P-17' 'FAIL' 'a prediction was falsified — see output above; revisits WP-D6, not the probe' }
    default { Add-Result 'P-17' 'UNRUN' "no transport crossed a session boundary (exit $p17Exit) — see the probe output for which host reused the token; not a pass" }
}

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '== SUMMARY ==' -ForegroundColor Cyan
$results | Format-Table -AutoSize

Write-Host "Machine: $env:COMPUTERNAME  Build: $([System.Environment]::OSVersion.Version)"
Write-Host 'Record any SECTION 3 result in docs/design/WINDOWS_WALLET_PROBE_SHEET.md §4.'

if ($failed -gt 0) {
    Write-Host "$failed probe group(s) FAILED." -ForegroundColor Red
    exit 1
}
# "All run probes passed" means no FAIL. A non-FAIL status is not a pass, and
# the disclaimer names every one that can appear so a reader scanning only this
# line cannot mistake an unreached question for a green: UNRUN (the probe could
# not reach what it measures), TODO (not implemented on this host), SKIP
# (pre-declared out of scope for this mode). None increments $failed; none is a
# pass.
Write-Host 'No probe FAILED. UNRUN / TODO / SKIP rows are not passes — read their detail.' -ForegroundColor Green
exit 0
