<#
.SYNOPSIS
    Run Find-PAN (bin\find-pan.py) on Windows (PowerShell) from any directory, in the project's own environment.

.DESCRIPTION
    Every argument is passed to find-pan.py unchanged and its exit status is returned. The working directory is
    NOT changed, so relative --path / --file / --csv values mean what they say in your shell.

    The environment is the one bin\setup-env.ps1 configures (.venv-windows); an existing UV_PROJECT_ENVIRONMENT
    wins. uv is used when it is installed (it also brings the environment up to date); otherwise the
    environment's own Python is used if it exists.

.EXAMPLE
    PS> .\bin\find-pan.ps1 --path D:\data --mask --summary-json summary.json

.EXAMPLE
    PS> .\bin\find-pan.ps1 --version
#>

$ErrorActionPreference = 'Stop'

$BinDirectory = $PSScriptRoot
$ProjectRoot = Split-Path -Parent $BinDirectory
$Launcher = Join-Path $BinDirectory 'find-pan.py'

$Environment = if ($env:UV_PROJECT_ENVIRONMENT) { $env:UV_PROJECT_ENVIRONMENT } else { '.venv-windows' }

$Uv = Get-Command uv -ErrorAction SilentlyContinue
if ($Uv) {
    $env:UV_PROJECT_ENVIRONMENT = $Environment
    & $Uv.Source run --project $ProjectRoot python $Launcher @args
    exit $LASTEXITCODE
}

#   No uv: use the environment's Python if it has been created.
$EnvironmentDirectory = if ([System.IO.Path]::IsPathRooted($Environment)) { $Environment } else { Join-Path $ProjectRoot $Environment }
$Python = Join-Path $EnvironmentDirectory 'Scripts\python.exe'
if (Test-Path -LiteralPath $Python) {
    & $Python $Launcher @args
    exit $LASTEXITCODE
}

[Console]::Error.WriteLine(@"
find-pan.ps1: uv was not found and there is no environment at $EnvironmentDirectory.
Install uv (winget install --id=astral-sh.uv -e) and run bin\setup-env.ps1.
"@)
exit 1
