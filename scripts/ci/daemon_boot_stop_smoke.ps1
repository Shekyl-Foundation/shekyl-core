# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Boot the built daemon offline on regtest with a fresh data directory and a
# free RPC port, wait until it answers get_info, ask it to stop over RPC, and
# assert that it exits 0 within a timeout and created its chain store.
#
# This is the Windows job's daemon gate. It proves what a release needs from
# the binary: it starts, it serves, it stops cleanly on request, and it leaves
# a store behind. It replaces the daemonizer-removal smoke test, which
# re-proved the link, asserted that a deleted code path did nothing, and
# pinned the removed_flags shim the daemon-configuration cutover deletes
# (DAEMON_CONFIG_CUTOVER.md, DC-Q4); its `--help` check returned before the
# logger was initialised, so it exercised less than it claimed.
#
# Written for PowerShell 7 and runnable on any platform, so it can be run by
# hand against a Linux build. The spellings are today's; the cutover moves
# them to INPUT_GRAMMAR.md's names in the same change that renames them.
#
# Rule 47: every check below asserts its own subject. A daemon that never
# answers is a failure, not a skipped check; a store that is missing is a
# failure, not a quiet pass.

param(
    [Parameter(Mandatory = $true)] [string] $Daemon,
    [int] $StartTimeoutSeconds = 120,
    [int] $StopTimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $Daemon -PathType Leaf)) {
    throw "daemon binary not found at '$Daemon'"
}
$Daemon = (Resolve-Path -LiteralPath $Daemon).Path

# A free loopback port: bind port 0, read what the OS chose, release it.
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$rpcPort = $listener.LocalEndpoint.Port
$listener.Stop()

$dataDir = Join-Path ([System.IO.Path]::GetTempPath()) ("shekyld-smoke-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dataDir | Out-Null
$logFile = Join-Path $dataDir 'shekyld.log'
# Regtest is FAKECHAIN: the store lives under `fake`, then the LMDB directory.
$store = Join-Path (Join-Path (Join-Path $dataDir 'fake') 'lmdb') 'data.mdb'

$psi = [System.Diagnostics.ProcessStartInfo]::new($Daemon)
foreach ($a in @(
        '--regtest', '--offline', '--non-interactive',
        '--fixed-difficulty', '1',
        '--data-dir', $dataDir,
        '--rpc-bind-ip', '127.0.0.1',
        '--rpc-bind-port', "$rpcPort",
        '--log-file', $logFile,
        '--log-level', '1')) {
    $psi.ArgumentList.Add($a)
}
$psi.UseShellExecute = $false

$base = "http://127.0.0.1:$rpcPort"
$proc = $null
$failed = $true
try {
    Write-Host "starting $Daemon (data dir $dataDir, RPC port $rpcPort)"
    $proc = [System.Diagnostics.Process]::Start($psi)

    # 1. It serves: get_info answers OK before the start timeout.
    $deadline = [DateTime]::UtcNow.AddSeconds($StartTimeoutSeconds)
    $answered = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($proc.HasExited) {
            throw "the daemon exited with status $($proc.ExitCode) before answering get_info"
        }
        try {
            $body = '{"jsonrpc":"2.0","id":"0","method":"get_info"}'
            $info = Invoke-RestMethod -Method Post -Uri "$base/json_rpc" -Body $body `
                -ContentType 'application/json' -TimeoutSec 5 -NoProxy
            if ($info.result -and $info.result.status -eq 'OK') {
                $answered = $true
                Write-Host "get_info answered: height $($info.result.height)"
                break
            }
        } catch {
            # Not listening yet; poll again.
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $answered) {
        throw "the daemon did not answer get_info within $StartTimeoutSeconds s"
    }

    # 2. It stops on request, exits 0, within the stop timeout.
    $stop = Invoke-RestMethod -Method Post -Uri "$base/stop_daemon" -Body '{}' `
        -ContentType 'application/json' -TimeoutSec 10 -NoProxy
    if ($stop.status -ne 'OK') {
        throw "stop_daemon answered status '$($stop.status)'"
    }
    if (-not $proc.WaitForExit($StopTimeoutSeconds * 1000)) {
        throw "the daemon did not exit within $StopTimeoutSeconds s of stop_daemon"
    }
    if ($proc.ExitCode -ne 0) {
        throw "the daemon exited with status $($proc.ExitCode) after stop_daemon"
    }

    # 3. It created its store.
    if (-not (Test-Path -LiteralPath $store -PathType Leaf)) {
        throw "no chain store at '$store'"
    }

    Write-Host "PASS: started, answered get_info, stopped with status 0, store at $store"
    $failed = $false
} finally {
    if ($proc -and -not $proc.HasExited) {
        $proc.Kill($true)
        $proc.WaitForExit()
    }
    if ($failed -and (Test-Path -LiteralPath $logFile)) {
        Write-Host '--- last 60 lines of the daemon log ---'
        Get-Content -LiteralPath $logFile -Tail 60 | Write-Host
    }
    Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction SilentlyContinue
}
