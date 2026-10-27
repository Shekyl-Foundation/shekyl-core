# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The Windows MSVC job's static-CRT gate. Two stages, one subject each:
#
#   link        build the daemon, mdb_copy, the importer and core_tests;
#               each Rust-linking binary exists; the link log has no LNK4098.
#   core-tests  core_tests runs its suite and reports a positive run count
#               with zero failures.
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
    [ValidateSet('link', 'core-tests')]
    [string]$Stage
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location -LiteralPath $RepoRoot

# Output paths of the Rust-linking binaries. mdb_copy is built with them
# (the daemon's prune warning names shekyl-mdb-copy) and is not a subject:
# it does not link the Rust image.
$Shekyld = 'build\bin\Release\shekyld.exe'
$BlockchainImport = 'build\bin\Release\shekyl-blockchain-import.exe'
$CoreTests = 'build\tests\core_tests\Release\core_tests.exe'
$MsvcLinkSubjects = @($Shekyld, $BlockchainImport, $CoreTests)

$MsvcBuildTargets = @('daemon', 'mdb_copy', 'blockchain_import', 'core_tests')
# The runner's parallelism for this one build. A name, so the cmake line
# is not where the number lives.
$MsvcBuildParallelism = 2

$LinkLog = 'msvc-link.log'
$CoreTestsLog = 'core-tests.log'
$MixedRuntimeDiagnostic = 'LNK4098'
# chaingen_main.cpp's report. The count has to be present and positive;
# pinning today's suite size would fail the gate when a case is added.
$CoreTestsRunPattern = 'Test run: (\d+)'
$CoreTestsFailurePattern = 'Failures: (\d+)'
$CoreTestsReportMark = 'REPORT:'
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

function Get-LastCapture {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Pattern
    )
    $hits = Select-String -LiteralPath $Path -Pattern $Pattern
    if (-not $hits) {
        return $null
    }
    return [int]@($hits)[-1].Matches[0].Groups[1].Value
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
        Write-Host "MSVC link check: shekyld, shekyl-blockchain-import and core_tests linked; no ${MixedRuntimeDiagnostic}"
    }
    'core-tests' {
        if (-not (Test-Path -LiteralPath $CoreTests)) {
            Exit-Gate -Code 1 -Message "no ${CoreTests}: core_tests has no subject"
        }
        Invoke-LoggedNative -FilePath $CoreTests -ArgumentList @('--generate_and_play_test_data') `
            -LogPath $CoreTestsLog -FromPattern $CoreTestsReportMark
        if ($script:NativeExit -ne 0) {
            Exit-Gate -Code $script:NativeExit -Message "core_tests failed ($script:NativeExit)"
        }
        $testsRun = Get-LastCapture -Path $CoreTestsLog -Pattern $CoreTestsRunPattern
        $failures = Get-LastCapture -Path $CoreTestsLog -Pattern $CoreTestsFailurePattern
        if ($null -eq $testsRun -or $testsRun -lt 1) {
            Exit-Gate -Code 1 -Message "core_tests printed no positive 'Test run:' count"
        }
        if ($null -eq $failures -or $failures -ne 0) {
            Exit-Gate -Code 1 -Message "core_tests failures: $failures"
        }
        Write-Host "core_tests: $testsRun run, $failures failures"
    }
    default {
        Exit-Gate -Code 1 -Message "no gate for stage ${Stage}"
    }
}
