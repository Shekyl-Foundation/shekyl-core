# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The Windows job's daemon gate (DAEMON_CONFIG_CUTOVER.md §5.2). It proves
# what a release needs from the binary, and what the configuration cutover
# added to it:
#
#   1. boot: the built daemon, offline on regtest with a fresh data
#      directory and a free RPC port, answers get_info; while it runs its
#      data directory holds `shekyld.lock`;
#   2. lock: a second daemon on the same data directory is refused with
#      exit 2, naming the lock (DC-Q15);
#   3. stop: asked over RPC, the first daemon exits 0 within a timeout,
#      leaves its chain store, and leaves the `shekyld.network` marker
#      naming regtest and its network id (DC-Q15);
#   4. marker: a daemon on another network is refused that data directory
#      with exit 2, naming the marker;
#   5. configuration file: a file in a directory only this account and
#      administrators (and the platform's own principals) can write is
#      accepted; the same file after its
#      directory's access list grants Users write is refused with exit 2,
#      naming the permissions (§2.4). Windows only: the rule is the
#      access list's; on another platform the case prints that it did not
#      run.
#
# It replaces the daemonizer-removal smoke test, which re-proved the link,
# asserted that a deleted code path did nothing, and pinned the
# removed_flags shim the cutover deleted (DC-Q4); its `--help` check
# returned before the logger was initialised, so it exercised less than
# it claimed.
#
# Written for PowerShell 7 and runnable on any platform, so it can be run
# by hand against a Linux build. The spellings are INPUT_GRAMMAR.md's.
#
# Rule 47: every check below asserts its own subject. A daemon that never
# answers is a failure, not a skipped check (and the poll says what the
# last answer was); a store or a marker that is missing is a failure, not
# a quiet pass; a refusal is asserted by its exit status and its code.
#
# The Ctrl-Break case of §5.2 is not here: it needs a console on the
# runner, which the pre-flight line below reports (audit §5).

param(
    [Parameter(Mandatory = $true)] [string] $Daemon,
    [int] $StartTimeoutSeconds = 120,
    [int] $StopTimeoutSeconds = 60,
    [int] $RefusalTimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $Daemon -PathType Leaf)) {
    throw "daemon binary not found at '$Daemon'"
}
$Daemon = (Resolve-Path -LiteralPath $Daemon).Path

# Pre-flight (DAEMON_CONFIG_CUTOVER_AUDIT.md §5): does the runner's process
# have a console? Decides where the Ctrl-Break case can run. Reported, not
# assumed.
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

function New-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $port
}

# Starts the daemon with the given words, stdout and stderr captured to
# files under $work. Returns the process and the two file paths.
function Start-Shekyld {
    param([string[]] $Words, [string] $Label)
    $out = Join-Path $work "$Label.out"
    $err = Join-Path $work "$Label.err"
    $quoted = $Words | ForEach-Object { if ($_ -match '[\s"]') { '"' + $_.Replace('"', '\"') + '"' } else { $_ } }
    $proc = Start-Process -FilePath $Daemon -ArgumentList $quoted -RedirectStandardOutput $out `
        -RedirectStandardError $err -PassThru -NoNewWindow
    # Cache the handle now: without it, ExitCode is null for a child that
    # exits before the first read, and the refusal cases exit at once.
    $null = $proc.Handle
    return @{ Proc = $proc; Out = $out; Err = $err }
}

# Polls get_info on the admin listener. Keeps the last error, so a daemon
# that listens but answers with an HTTP error is reported as that error and
# not as a bare timeout.
function Wait-GetInfo {
    param([System.Diagnostics.Process] $Proc, [int] $Port, [int] $TimeoutSeconds, [string] $Label)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastError = 'no answer yet'
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Proc.HasExited) {
            throw "$Label exited with status $($Proc.ExitCode) before answering get_info"
        }
        try {
            $body = '{"jsonrpc":"2.0","id":"0","method":"get_info"}'
            $info = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/json_rpc" -Body $body `
                -ContentType 'application/json' -TimeoutSec 5 -NoProxy
            if ($info.result -and $info.result.status -eq 'OK') {
                Write-Host "${Label}: get_info answered, height $($info.result.height)"
                return
            }
            $lastError = "get_info answered without status OK: $($info | ConvertTo-Json -Compress -Depth 3)"
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 500
    }
    throw "$Label did not answer get_info within $TimeoutSeconds s; last error: $lastError"
}

# Starts the daemon expecting a refusal: exit 2 within the timeout, with
# the refusal's code on stderr.
function Assert-Refused {
    param([string[]] $Words, [string] $Label, [string] $Code)
    $run = Start-Shekyld -Words $Words -Label $Label
    $running.Add($run.Proc)
    if (-not $run.Proc.WaitForExit($RefusalTimeoutSeconds * 1000)) {
        throw "$Label was not refused: still running after $RefusalTimeoutSeconds s"
    }
    $stderr = if (Test-Path -LiteralPath $run.Err) { Get-Content -LiteralPath $run.Err -Raw } else { '' }
    if ($run.Proc.ExitCode -ne 2) {
        throw "$Label exited with status $($run.Proc.ExitCode), not the refusal status 2; stderr:`n$stderr"
    }
    if ($stderr -notmatch [regex]::Escape($Code)) {
        throw "$Label was refused without naming $Code; stderr:`n$stderr"
    }
    Write-Host "${Label}: refused with exit 2 naming $Code"
}

function Stop-OverRpc {
    param([System.Diagnostics.Process] $Proc, [int] $Port, [string] $Label)
    $stop = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/stop_daemon" -Body '{}' `
        -ContentType 'application/json' -TimeoutSec 10 -NoProxy
    if ($stop.status -ne 'OK') {
        throw "$Label stop_daemon answered status '$($stop.status)'"
    }
    if (-not $Proc.WaitForExit($StopTimeoutSeconds * 1000)) {
        throw "$Label did not exit within $StopTimeoutSeconds s of stop_daemon"
    }
    if ($Proc.ExitCode -ne 0) {
        throw "$Label exited with status $($Proc.ExitCode) after stop_daemon"
    }
    Write-Host "${Label}: stopped over RPC, exit 0"
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("shekyld-smoke-" + [guid]::NewGuid().ToString('N'))
$dataDir = Join-Path $work 'data'
$cfgDir = Join-Path $work 'config'
New-Item -ItemType Directory -Path $dataDir | Out-Null
New-Item -ItemType Directory -Path $cfgDir | Out-Null
$logFile = Join-Path $dataDir 'shekyld.log'
$store = Join-Path (Join-Path $dataDir 'lmdb') 'data.mdb'
$lockFile = Join-Path $dataDir 'shekyld.lock'
$markerFile = Join-Path $dataDir 'shekyld.network'

function Get-DaemonWords {
    param([string] $Network, [string] $Data, [int] $Port, [string] $Log, [string[]] $Extra = @())
    # `dev-difficulty` is a regtest-only row: on another network it is
    # refused at resolve (config.dev.network), before the data directory is
    # looked at, so the testnet daemon of case 4 must not carry it.
    $lever = if ($Network -eq 'regtest') { @('--dev-difficulty', '1') } else { @() }
    return @('--network', $Network, '--clearnet', 'off', '--tor', 'off') + $lever + @(
        '--data-dir', $Data, '--rpc-admin-listen', "127.0.0.1:$Port", '--log-file', $Log,
        '--log-level', 'warn') + $Extra
}

$running = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$failure = $null
try {
    # 1. boot
    $rpcPort = New-FreePort
    Write-Host "starting $Daemon (data dir $dataDir, RPC port $rpcPort)"
    $first = Start-Shekyld -Words (Get-DaemonWords -Network 'regtest' -Data $dataDir -Port $rpcPort -Log $logFile) -Label 'first'
    $running.Add($first.Proc)
    Wait-GetInfo -Proc $first.Proc -Port $rpcPort -TimeoutSeconds $StartTimeoutSeconds -Label 'first daemon'
    if (-not (Test-Path -LiteralPath $lockFile -PathType Leaf)) {
        throw "no lock at '$lockFile' while the daemon runs"
    }

    # 2. lock: a second daemon on the same data directory
    $secondPort = New-FreePort
    Assert-Refused -Words (Get-DaemonWords -Network 'regtest' -Data $dataDir -Port $secondPort -Log (Join-Path $work 'second.log')) `
        -Label 'second daemon on the same data directory' -Code 'config.data-dir.locked'
    if ($first.Proc.HasExited) {
        throw "the first daemon exited (status $($first.Proc.ExitCode)) while the second was refused"
    }

    # 3. stop, store, marker
    Stop-OverRpc -Proc $first.Proc -Port $rpcPort -Label 'first daemon'
    if (-not (Test-Path -LiteralPath $store -PathType Leaf)) {
        throw "no chain store at '$store'"
    }
    if (-not (Test-Path -LiteralPath $markerFile -PathType Leaf)) {
        throw "no network marker at '$markerFile' after the run"
    }
    $marker = Get-Content -LiteralPath $markerFile -Raw
    if ($marker -notmatch '(?m)^network = "regtest"$') {
        throw "the marker does not name regtest:`n$marker"
    }
    if ($marker -notmatch '(?m)^network-id = "[0-9a-f]{32}"$') {
        throw "the marker does not hold a 32-hex network id:`n$marker"
    }
    Write-Host 'marker names regtest and its network id'

    # 4. marker: another network on the same data directory
    Assert-Refused -Words (Get-DaemonWords -Network 'testnet' -Data $dataDir -Port (New-FreePort) -Log (Join-Path $work 'testnet.log')) `
        -Label 'testnet daemon on the regtest data directory' -Code 'config.marker.network'

    # 5. configuration file permissions (Windows access lists)
    if ($IsWindows) {
        $cfgFile = Join-Path $cfgDir 'shekyld-regtest.toml'
        Set-Content -LiteralPath $cfgFile -Value 'log-level = "warn"' -NoNewline
        $cfgData = Join-Path $work 'cfgdata'
        New-Item -ItemType Directory -Path $cfgData | Out-Null
        $cfgPort = New-FreePort
        $cfgRun = Start-Shekyld -Words (Get-DaemonWords -Network 'regtest' -Data $cfgData -Port $cfgPort -Log (Join-Path $cfgData 'shekyld.log') -Extra @('--config-file', $cfgFile)) -Label 'config-accepted'
        $running.Add($cfgRun.Proc)
        Wait-GetInfo -Proc $cfgRun.Proc -Port $cfgPort -TimeoutSeconds $StartTimeoutSeconds -Label 'daemon with a config file in a private directory'
        Stop-OverRpc -Proc $cfgRun.Proc -Port $cfgPort -Label 'daemon with a config file'
        # Grant BUILTIN\Users write on the directory (S-1-5-32-545, by SID so
        # the runner's locale cannot rename it away).
        $icacls = & icacls $cfgDir /grant '*S-1-5-32-545:(OI)(CI)W' 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "icacls could not grant Users write on '$cfgDir': $icacls"
        }
        Assert-Refused -Words (Get-DaemonWords -Network 'regtest' -Data (Join-Path $work 'cfgdata2') -Port (New-FreePort) -Log (Join-Path $work 'cfg2.log') -Extra @('--config-file', $cfgFile)) `
            -Label 'daemon with a config file whose directory grants Users write' -Code 'config.file.permissions'
    } else {
        Write-Host 'configuration-file access-list case: not run (Windows access lists only)'
    }
} catch {
    $failure = $_
}

$teardownErrors = [System.Collections.Generic.List[string]]::new()
foreach ($p in $running) {
    try {
        if (-not $p.HasExited) {
            $p.Kill($true)
        }
        if (-not $p.WaitForExit(10000)) {
            $teardownErrors.Add("a daemon (pid $($p.Id)) was still running 10 s after it was killed")
        }
    } catch {
        if (-not $p.HasExited) {
            $teardownErrors.Add("could not stop a daemon (pid $($p.Id)): $($_.Exception.Message)")
        }
    }
}
if ($failure) {
    foreach ($f in Get-ChildItem -LiteralPath $work -Recurse -Include '*.log', '*.err' -File -ErrorAction SilentlyContinue) {
        Write-Host "--- last 40 lines of $($f.FullName) ---"
        Get-Content -LiteralPath $f.FullName -Tail 40 | Write-Host
    }
}
# Remove the work directory. Windows can hold a file handle briefly after a
# process exits, so a failed removal is retried before it counts.
$removeError = $null
for ($i = 0; $i -lt 10 -and (Test-Path -LiteralPath $work); $i++) {
    try {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Stop
    } catch {
        $removeError = $_
        Start-Sleep -Milliseconds 500
    }
}
if (Test-Path -LiteralPath $work) {
    $teardownErrors.Add("could not remove the work directory '$work': $($removeError.Exception.Message)")
}
if ($failure) {
    foreach ($e in $teardownErrors) { Write-Warning "teardown: $e" }
    throw $failure
}
if ($teardownErrors.Count -gt 0) {
    throw ("teardown: " + ($teardownErrors -join '; '))
}
$cases = if ($IsWindows) { 'boot, lock, stop, store, marker, other-network refusal, config-file access list' } else { 'boot, lock, stop, store, marker, other-network refusal' }
Write-Host "daemon smoke: $cases all asserted"
