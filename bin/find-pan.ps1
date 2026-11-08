<#
.SYNOPSIS
    Run Find-PAN (bin\find-pan.py) with PowerShell from any directory, in the project's own environment.

.DESCRIPTION
    Every argument is passed to find-pan.py unchanged and its exit status is returned. The working directory is
    NOT changed, so relative --path / --file / --csv values mean what they say in your shell.

    FIND_PAN_HOME selects the project root and its .venv. If unset, the parent of this script's bin directory is used.

.EXAMPLE
    PS> .\bin\find-pan.ps1 --path D:\data --mask --summary-json summary.json

.EXAMPLE
    PS> .\bin\find-pan.ps1 --version
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = if ($env:FIND_PAN_HOME) { $env:FIND_PAN_HOME } else { Split-Path -Parent $PSScriptRoot }
$Launcher = Join-Path $ProjectRoot 'bin\find-pan.py'

$EnvironmentDirectory = Join-Path $ProjectRoot '.venv'

if (-not (Test-Path -LiteralPath $Launcher -PathType Leaf)) {
    [Console]::Error.WriteLine("find-pan.ps1: launcher not found at $Launcher. Check FIND_PAN_HOME.")
    exit 1
}

$PythonRelative = if ([System.IO.Path]::DirectorySeparatorChar -eq '\') { 'Scripts\python.exe' } else { 'bin/python' }
$Python = Join-Path $EnvironmentDirectory $PythonRelative
if (Test-Path -LiteralPath $Python -PathType Leaf) {
    & $Python $Launcher @args
    exit $LASTEXITCODE
}

[Console]::Error.WriteLine(@"
find-pan.ps1: Python was not found in $EnvironmentDirectory.
Run the setup script in $ProjectRoot\bin\setup-env.ps1.
"@)
exit 1
