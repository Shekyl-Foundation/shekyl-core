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
# hand against a Linux build. The spellings are INPUT_GRAMMAR.md's: the
# daemon parses its arguments in Rust from the configuration cutover's
# commit (b) on.
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

# Whether this process has a console. A Ctrl-Break stop case needs one,
# because GenerateConsoleCtrlEvent reaches only processes that share the
# caller's console (DAEMON_CONFIG_CUTOVER.md §9, pre-flight item 5). Reported
# on every run, so the answer is read off the job rather than assumed.
if ($IsWindows) {
    Add-Type -Namespace ShekylSmoke -Name Console -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[DllImport("kernel32.dll", SetLastError = true)] public static extern uint GetConsoleProcessList(uint[] list, uint count);
'@
    $consoleIds = [uint32[]]::new(64)
    $attached = [ShekylSmoke.Console]::GetConsoleProcessList($consoleIds, 64)
    $window = if ([ShekylSmoke.Console]::GetConsoleWindow() -eq [IntPtr]::Zero) { 'none' } else { 'present' }
    Write-Host "runner console: $attached process(es) attached, window $window"
}

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
        '--network', 'regtest',
        '--clearnet', 'off', '--tor', 'off',
        '--dev-difficulty', '1',
        '--data-dir', $dataDir,
        '--rpc-admin-listen', "127.0.0.1:$rpcPort",
        '--log-file', $logFile,
        '--log-level', 'warn')) {
    $psi.ArgumentList.Add($a)
}
$psi.UseShellExecute = $false

$base = "http://127.0.0.1:$rpcPort"
$proc = $null
# The first failure is the verdict. Teardown runs whatever happened, never
# replaces that failure, and fails a run that otherwise passed.
$failure = $null
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
} catch {
    $failure = $_
}

# Teardown. Each step runs on its own; none of them throws.
$teardownErrors = [System.Collections.Generic.List[string]]::new()

# Stop the daemon if it is still running. A process that exits between the
# check and the kill is a stopped process, not a teardown error.
if ($proc) {
    try {
        if (-not $proc.HasExited) {
            $proc.Kill($true)
        }
        if (-not $proc.WaitForExit(10000)) {
            $teardownErrors.Add("the daemon (pid $($proc.Id)) was still running 10 s after it was killed")
        }
    } catch {
        if (-not $proc.HasExited) {
            $teardownErrors.Add("could not stop the daemon (pid $($proc.Id)): $($_.Exception.Message)")
        }
    }
}

if ($failure -and (Test-Path -LiteralPath $logFile)) {
    Write-Host '--- last 60 lines of the daemon log ---'
    Get-Content -LiteralPath $logFile -Tail 60 | Write-Host
}

# Remove the data directory. Windows can hold a file handle briefly after a
# process exits, so a failed removal is retried before it counts.
$removeError = $null
for ($i = 0; $i -lt 10 -and (Test-Path -LiteralPath $dataDir); $i++) {
    try {
        Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction Stop
    } catch {
        $removeError = $_
        Start-Sleep -Milliseconds 500
    }
}
if (Test-Path -LiteralPath $dataDir) {
    $teardownErrors.Add("could not remove the data directory '$dataDir': $($removeError.Exception.Message)")
}

if ($failure) {
    foreach ($e in $teardownErrors) { Write-Warning "teardown: $e" }
    throw $failure
}
if ($teardownErrors.Count -gt 0) {
    throw ("the smoke test passed but its teardown failed: " + ($teardownErrors -join '; '))
}
Write-Host "PASS: started, answered get_info, stopped with status 0, created its store, and cleaned up"
