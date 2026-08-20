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
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$results = [System.Collections.ArrayList]::new()
$failed = 0

function Add-Result {
    param($Id, $Status, $Detail)
    [void]$results.Add([pscustomobject]@{ Probe = $Id; Status = $Status; Detail = $Detail })
    if ($Status -eq 'FAIL') { $script:failed++ }
}

# ---------------------------------------------------------------------------
# GATE 0 — the copied WP-D9 probe must not be stale.
#
# shekyl-engine-core carries TLS (`ring`), so its Windows disk probe cannot be
# cross-compiled from a Linux box and the probe suite holds a copy of it. A
# suite that exercises a STALE copy measures nothing — the same defect class as
# a grep gate that passes because its path vanished.
#
# The comparison lives in check_win_probe_copy.py rather than here, and that is
# deliberate: it is the load-bearing logic, PowerShell cannot be executed on the
# development box, and a gate whose only implementation is unverifiable is the
# thing this round keeps finding. The Python version was tested against three
# injected drifts (swapped out-param, dropped error branch, reworded safety
# comment) and refused all three. This script calls it; there is one comparison
# and it is the tested one.
# ---------------------------------------------------------------------------
Write-Host '== GATE 0: WP-D9 copy is not stale ==' -ForegroundColor Cyan

python (Join-Path $repo 'scripts/ci/check_win_probe_copy.py')
if ($LASTEXITCODE -ne 0) {
    Write-Host 'GATE 0 failed — nothing below would be trustworthy, so stopping here.' -ForegroundColor Red
    exit 2
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
    cargo test -p shekyl-win-sec --features test-utils --test probes -- --nocapture
    $cargoExit = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($cargoExit -eq 0) {
    Add-Result 'P-1,2,3,5,6,7,8,9' 'PASS' 'cargo test -p shekyl-win-sec --test probes'
} else {
    Add-Result 'P-1,2,3,5,6,7,8,9' 'FAIL' "cargo exited $cargoExit — see output above; the sheet names which decision each revisits"
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
        $printed = cargo run -q -p shekyl-win-sec --features test-utils --example print_sid 2>$null
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
    # NOT YET IMPLEMENTED, and reported as such rather than quietly passing.
    # It needs a Low-integrity child (a restricted token derived from the
    # interactive one), which is real work and belongs with WP-W2's transport
    # rather than being faked here. A blank in the sheet is a finding; so is
    # this line.
    Add-Result 'P-12' 'TODO' 'needs a Low-IL child process — lands with WP-W2; result goes in the sheet §4'
    Add-Result 'P-13' 'TODO' 'needs two interactive logons — manual, result goes in the sheet §4'
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
Write-Host 'All run probes passed. TODO/SKIP rows are not passes.' -ForegroundColor Green
exit 0
