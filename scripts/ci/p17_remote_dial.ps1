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
    SMB connection lands in a network logon with that user's SID and a distinct
    logon SID — same user, different session, which is exactly WP-D6's case.

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

# Open a named pipe on $Server as this user; return the Win32 error (0 = opened).
# The stream is closed immediately on success — this probe measures whether the
# open is permitted, nothing more. Default impersonation carries our identity
# over SMB.
function Try-Open([string]$role) {
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(
        $Server, (Pipe-Name $role),
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None,
        [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
    try {
        $client.Connect(30000)   # bounded, like the Rust side
        $client.Dispose()
        return 0
    }
    catch [System.ComponentModel.Win32Exception] {
        return $_.Exception.NativeErrorCode
    }
    catch [System.TimeoutException] {
        # No instance answered within the window. Distinct from a refusal:
        # report a sentinel the server will treat as "did not measure".
        return 258   # WAIT_TIMEOUT, reused as "no answer"
    }
    finally { if ($client) { $client.Dispose() } }
}

# Steps 1 and 2 first, so their results can be reported through step 3.
$daclErr = Try-Open 'daclonly'
Write-Host "  daclonly open -> os error $daclErr (expect 5 = ERROR_ACCESS_DENIED)"
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
    Write-Host "P-17 dial UNRUN: could not open the control pipe: $($_.Exception.Message)"
    Write-Host "  If this is ERROR_ACCESS_DENIED, the control pipe (granted to the USER SID)"
    Write-Host "  refused us — which means we are not the same AD user as the server."
    exit 2
}
$line = "$daclErr $prodErr"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($line)
$control.Write($bytes, 0, $bytes.Length)
$control.Flush()
$control.Dispose()

Write-Host "P-17 dial: reported `"$line`" through the control pipe. Read the server's verdict on $Server."
exit 0
