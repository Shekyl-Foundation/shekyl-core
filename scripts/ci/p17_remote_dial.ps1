# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

<#
.SYNOPSIS
    P-17 remote dial — the client half of the two-machine WP-D6 IPC$ test.

.DESCRIPTION
    Runs on the SECOND, domain-joined machine (which need not be a developer
    box: this uses only .NET's built-in NamedPipeClientStream, no toolchain).
    It must run as the SAME AD user the server (`p17… --serve`) runs as, so the
    SMB connection lands in a network logon carrying that user's SID but — as
    the probe sheet §4.8 confirmed — no logon SID at all. That absence is
    exactly WP-D6's case: a logon-SID-only DACL is unmatchable from the network,
    while the present user SID makes the refusal attributable.

    It attempts the three pipes the server stood up, in the server's stated
    order, and reports the two refusals back through the control pipe it is
    allowed to open. The server combines that with the caller identity it reads
    off the impersonation token and prints the single verdict.

    Names are DETERMINISTIC from the shared user SID (same AD user on both
    machines) plus a fixed `-p17-<role>` discriminator — no exchange. This must
    match `p17_pipe_name` in the Rust probe exactly; if the server's "ready"
    line prints different names, they have diverged and the run is meaningless.

.PARAMETER Server
    The server's host name, e.g. LP7760-W1XMP6G3.

.EXAMPLE
    pwsh scripts/ci/p17_remote_dial.ps1 -Server LP7760-W1XMP6G3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Server
)

$ErrorActionPreference = 'Stop'

# The user SID this client authenticates as. Must equal the server's, or the
# refusal is over-determined (a different user is not in the DACL at all) — the
# server also checks this and reports UNRUN if they differ, but naming keys on
# it too, so a mismatch here dials the wrong pipe entirely.
$mySid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
Write-Host "P-17 dial: authenticating as SID $mySid to \\$Server"

# Must match `p17_pipe_name(user_sid, role)` in the Rust probe.
function Pipe-Name([string]$role) { "shekyl-wallet-$mySid-p17-$role" }

# Map a PowerShell error record from a pipe open to a Win32-ish error code.
#
# The subtlety that makes this the load-bearing function: PowerShell wraps any
# exception thrown by a .NET **method or constructor** in
# `MethodInvocationException`, so a typed `catch [Win32Exception]` never matches
# — the real exception is down the `InnerException` chain. And the exception
# this probe most needs to survive is `UnauthorizedAccessException` ("Access to
# the path is denied"), which is the PREDICTED, PASS-confirming result of steps
# 1 and 2. A catch that missed it would abort the client on the exact outcome
# the probe exists to observe, and the server would then report "no caller
# connected" — the correct answer made unreportable and misread as a network
# fault. So this walks the whole chain.
function Map-PipeError($record) {
    $ex = $record.Exception
    while ($ex) {
        if ($ex -is [System.TimeoutException]) { return 258 }          # WAIT_TIMEOUT sentinel: no instance answered
        if ($ex -is [System.UnauthorizedAccessException]) { return 5 } # ERROR_ACCESS_DENIED — the refusal we test for
        if ($ex -is [System.ComponentModel.Win32Exception]) { return $ex.NativeErrorCode }
        $ex = $ex.InnerException
    }
    # Nothing on the chain was a type we map: best-effort low word of the top
    # HResult (HRESULT_FROM_WIN32 keeps the Win32 code in the low 16 bits).
    return ($record.Exception.HResult -band 0xFFFF)
}

# Open a named pipe on $Server as this user; return the Win32 error (0 = opened).
# The stream is closed on the way out — this probe measures whether the open is
# permitted, nothing more. Default impersonation carries our identity over SMB.
# It NEVER throws: a refusal is data, and every path returns a code.
function Try-Open([string]$role) {
    $client = $null
    try {
        $client = New-Object System.IO.Pipes.NamedPipeClientStream(
            $Server, (Pipe-Name $role),
            [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::None,
            [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
        $client.Connect(30000)   # bounded, like the Rust side
        return 0
    }
    catch {
        return (Map-PipeError $_)
    }
    finally { if ($client) { $client.Dispose() } }
}

# Steps 1 and 2 first, so their results can be reported through step 3.
$daclErr = Try-Open 'daclonly'
Write-Host "  daclonly open -> os error $daclErr (remote: expect 5 = ERROR_ACCESS_DENIED; on a same-box dry-run 0 is correct — the server's verdict is authoritative)"
$prodErr = Try-Open 'prod'
Write-Host "  prod open     -> os error $prodErr (expect refused)"

# Step 3: open the control pipe (we are granted the user SID, so this must
# succeed) and write the one-line report the server reads.
$control = New-Object System.IO.Pipes.NamedPipeClientStream(
    $Server, (Pipe-Name 'control'),
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
try {
    $control.Connect(30000)
}
catch {
    $code = Map-PipeError $_
    Write-Host "P-17 dial UNRUN: could not open the control pipe (os error $code)."
    if ($code -eq 5) {
        Write-Host "  ERROR_ACCESS_DENIED on the control pipe, which is granted to the USER SID:"
        Write-Host "  we are NOT the same AD user as the server. Log in as the same AD user the server runs as."
    }
    $control.Dispose()
    exit 2
}
$line = "$daclErr $prodErr"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($line)
$control.Write($bytes, 0, $bytes.Length)
$control.Flush()
$control.Dispose()

Write-Host "P-17 dial: reported `"$line`" through the control pipe. Read the server's verdict on $Server."
exit 0
