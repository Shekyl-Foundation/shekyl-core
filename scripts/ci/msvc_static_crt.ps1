# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The Windows MSVC job's static-CRT gate. One stage:
#
#   link        build the daemon; shekyld exists; the link log has no LNK4098.
#
# The log is a file. The native exit is $LASTEXITCODE, read on the next
# line, never the status of a pipe (rule 46). A missing binary, an empty
# log, or a missing report is a failure (rule 47).
#
# $PSNativeCommandUseErrorActionPreference is off around the native
# command. On the GitHub Windows runner that preference turns a non-zero
# exit into a terminating error before $LASTEXITCODE is read, and the log
# the redirect just wrote never reaches the step.

param(
    [Parameter(Mandatory)]
    [ValidateSet('link')]
    [string]$Stage
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location -LiteralPath $RepoRoot

# Output path of the Rust-linking daemon. The importer, mdb_copy and
# core_tests went with the C++ chain.
$Shekyld = 'build\bin\Release\shekyld.exe'
$MsvcLinkSubjects = @($Shekyld)

$MsvcBuildTargets = @('daemon')
# The runner's parallelism for this one build. A name, so the cmake line
# is not where the number lives.
$MsvcBuildParallelism = 2

$LinkLog = 'msvc-link.log'
$MixedRuntimeDiagnostic = 'LNK4098'
# Display only, and only when the report mark is absent. The verdict
# reads the whole file.
$LogTailWhenReportMissing = 40

function Exit-Gate {
    param(
        [Parameter(Mandatory)][int]$Code,
        [Parameter(Mandatory)][string]$Message
    )
    # Write-Host, not Write-Error. Under $ErrorActionPreference Stop,
    # Write-Error terminates before `exit` and the caller's code is lost.
    Write-Host $Message
    exit $Code
}

function Show-Log {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$FromPattern
    )
    if ($FromPattern) {
        # Select-String returns $null when nothing matches. Wrapping that
        # in @() is a one-element array, so the emptiness test is the
        # value itself.
        $marks = Select-String -LiteralPath $Path -Pattern $FromPattern
        if ($marks) {
            $skip = @($marks)[-1].LineNumber - 1
            Get-Content -LiteralPath $Path | Select-Object -Skip $skip
            return
        }
        Get-Content -LiteralPath $Path | Select-Object -Last $LogTailWhenReportMissing
        return
    }
    Get-Content -LiteralPath $Path
}

function Invoke-LoggedNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$LogPath,
        [string]$FromPattern
    )
    # Local to this function, which is the scope that launches the command.
    $PSNativeCommandUseErrorActionPreference = $false
    & $FilePath @ArgumentList *> $LogPath
    if ($null -eq $LASTEXITCODE) {
        Exit-Gate -Code 1 -Message "no exit code from ${FilePath}: the gate has no subject"
    }
    $script:NativeExit = $LASTEXITCODE
    if (-not (Test-Path -LiteralPath $LogPath) -or (Get-Item -LiteralPath $LogPath).Length -eq 0) {
        Exit-Gate -Code 1 -Message "no log at ${LogPath}: the gate has no subject"
    }
    Show-Log -Path $LogPath -FromPattern $FromPattern
}

switch ($Stage) {
    'link' {
        $cmakeArguments = @(
            '--build', 'build',
            '--config', 'Release',
            '--target'
        ) + $MsvcBuildTargets + @('--parallel', "$MsvcBuildParallelism")
        Invoke-LoggedNative -FilePath 'cmake' -ArgumentList $cmakeArguments -LogPath $LinkLog
        if ($script:NativeExit -ne 0) {
            Exit-Gate -Code $script:NativeExit -Message "the build failed ($script:NativeExit)"
        }
        foreach ($subject in $MsvcLinkSubjects) {
            if (-not (Test-Path -LiteralPath $subject)) {
                Exit-Gate -Code 1 -Message "no ${subject}: the link check has no subject"
            }
        }
        $mixed = Select-String -LiteralPath $LinkLog -Pattern $MixedRuntimeDiagnostic
        if ($mixed) {
            foreach ($hit in @($mixed)) { Write-Host $hit.Line }
            Exit-Gate -Code 1 -Message "a link warned ${MixedRuntimeDiagnostic}: two C runtimes in one image"
        }
        Write-Host "MSVC link check: shekyld linked; no ${MixedRuntimeDiagnostic}"
    }
    default {
        Exit-Gate -Code 1 -Message "no gate for stage ${Stage}"
    }
}
